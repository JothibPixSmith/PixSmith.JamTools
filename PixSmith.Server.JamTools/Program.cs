using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using PixSmith.Server.JamTools.Authentication;

var builder = WebApplication.CreateBuilder(args);

var oidc = builder.Configuration.GetSection("Oidc");

// ─── Sign-in: authorization code + PKCE against the PixSmith auth server ───────
//
// This host is the confidential client (a "backend for frontend"): it does the code
// exchange, and the resulting tokens stay here. The SPA never sees a token and never
// sees a credential — the login form lives on the auth server, which is what makes
// single sign-on and MFA possible at all.

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ITicketStore, ServerSideTicketStore>();

// The ticket store is what moves the tokens off the cookie and into server memory.
builder.Services
	.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
	.Configure<ITicketStore>((options, store) => options.SessionStore = store);

builder.Services.AddAuthentication(options =>
	{
		options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
		options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
	})
	.AddCookie(options =>
	{
		options.Cookie.Name = "jamtools.session";
		options.Cookie.HttpOnly = true;
		options.Cookie.SameSite = SameSiteMode.Lax;
		options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
		options.ExpireTimeSpan = TimeSpan.FromHours(8);
		options.SlidingExpiration = true;

		// A SPA calling /api/auth/session wants a 401 it can branch on, not a
		// redirect to a login page that would arrive as opaque HTML.
		options.Events.OnRedirectToLogin = context =>
		{
			context.Response.StatusCode = StatusCodes.Status401Unauthorized;
			return Task.CompletedTask;
		};
	})
	.AddOpenIdConnect(options =>
	{
		options.Authority = oidc["Authority"];
		options.ClientId = oidc["ClientId"];
		options.ClientSecret = oidc["ClientSecret"];

		// The auth server runs on plain http in development; metadata retrieval
		// would refuse that otherwise.
		options.RequireHttpsMetadata = false;

		options.ResponseType = OpenIdConnectResponseType.Code;
		options.UsePkce = true;
		options.SaveTokens = true;          // tokens ride in the ticket → ticket store → server memory
		options.MapInboundClaims = false;   // keep the short JWT claim names (sub, name, role)

		options.CallbackPath = "/signin-oidc";
		options.SignedOutCallbackPath = "/signout-callback-oidc";

		options.Scope.Clear();
		foreach (var scope in oidc.GetSection("Scopes").Get<string[]>() ?? [])
			options.Scope.Add(scope);

		options.TokenValidationParameters = new TokenValidationParameters
		{
			NameClaimType = "name",
			RoleClaimType = "role",
		};

		// The handler defaults to response_mode=form_post, which brings the user back
		// as a cross-site POST — and a cross-site POST does not carry SameSite=Lax
		// cookies, so the correlation cookie below would be dropped and the callback
		// would fail with "Correlation failed". Chrome's Lax+POST heuristic hides that
		// for the first two minutes, which is just long enough to look like it works
		// until someone takes their time over the login form. A query response mode
		// makes the return leg a top-level GET, where Lax cookies are sent.
		// Serving this app over https instead would allow form_post with
		// SameSite=None + Secure.
		options.ResponseMode = OpenIdConnectResponseMode.Query;

		// Over plain http, SameSite=None would require Secure and the browser would
		// drop these outright.
		options.CorrelationCookie.SameSite = SameSiteMode.Lax;
		options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
		options.NonceCookie.SameSite = SameSiteMode.Lax;
		options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

		// Anything that goes wrong on the way back — the user cancelling, an expired
		// code, a clock skew — otherwise surfaces as an unhandled exception and a raw
		// 500 page. Send them back to the sign-in page instead; the detail is already
		// in the server log.
		options.Events.OnRemoteFailure = context =>
		{
			context.Response.Redirect("/login?error=signin_failed");
			context.HandleResponse();
			return Task.CompletedTask;
		};
	});

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	// Lets the browser attach to the WASM runtime for client-side C# debugging.
	app.UseWebAssemblyDebugging();
}
else
{
	app.UseHsts();
	app.UseHttpsRedirection();
}

// index.html carries the importmap naming every fingerprinted asset, so a cached
// copy outlives the build it belongs to: after a rebuild the browser asks for a
// dotnet.<old-hash>.js that no longer exists and Blazor dies with "Failed to fetch
// dynamically imported module". The fingerprinted assets are immutable and may be
// cached hard; the page that names them must always be revalidated.
var noCacheHtml = new StaticFileOptions
{
	OnPrepareResponse = context =>
	{
		if (context.File.Name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
		{
			context.Context.Response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
			context.Context.Response.Headers.Pragma = "no-cache";
			context.Context.Response.Headers.Expires = "0";
		}
	}
};

// Serves _framework/* (blazor.webassembly.js, the dotnet runtime, the app dlls).
app.UseBlazorFrameworkFiles();
app.UseStaticFiles(noCacheHtml);

app.UseAuthentication();
app.UseAuthorization();

var api = app.MapGroup("/api");

api.MapGet("/health", () => Results.Ok(new
{
	status = "ok",
	environment = app.Environment.EnvironmentName,
	utc = DateTimeOffset.UtcNow
}));

// ─── Auth endpoints ───────────────────────────────────────────────────────────

// Full-page navigation, not fetch: the browser has to follow the redirect to the
// auth server for the sign-in to be a top-level navigation.
api.MapGet("/auth/login", (string? returnUrl) => Results.Challenge(
	new AuthenticationProperties { RedirectUri = LocalPathOrDefault(returnUrl, "/success") },
	[OpenIdConnectDefaults.AuthenticationScheme]));

api.MapGet("/auth/logout", () => Results.SignOut(
	new AuthenticationProperties { RedirectUri = "/" },
	[CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

// What the Success page reads. Answers for signed-out callers too, so the SPA can
// tell "not signed in" apart from "something broke".
api.MapGet("/auth/session", async (HttpContext context) =>
{
	var user = context.User;
	if (user.Identity?.IsAuthenticated != true)
		return Results.Ok(new { authenticated = false });

	var accessToken = await context.GetTokenAsync("access_token");
	var expiresAt = await context.GetTokenAsync("expires_at");

	return Results.Ok(new
	{
		authenticated = true,
		subject = user.FindFirst("sub")?.Value,
		name = user.Identity.Name ?? user.FindFirst("name")?.Value,
		email = user.FindFirst("email")?.Value,
		roles = user.FindAll("role").Select(c => c.Value).ToArray(),
		token = new
		{
			type = await context.GetTokenAsync("token_type") ?? "Bearer",
			expiresAt,
			hasIdToken = await context.GetTokenAsync("id_token") is not null,
			hasRefreshToken = await context.GetTokenAsync("refresh_token") is not null,
			length = accessToken?.Length ?? 0,
			// Held server-side; returned only so the Success page can show what
			// arrived. Drop this field once you no longer need to eyeball it.
			accessToken,
		},
		claims = user.Claims
			.GroupBy(c => c.Type)
			.ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray()),
	});
});

// Anything that isn't a file or an API route is handed to the SPA router. The
// fallback serves index.html on its own path, so it needs the same no-cache rule.
app.MapFallbackToFile("index.html", noCacheHtml);

app.Run();

// Never redirect off-site on the strength of a query string.
static string LocalPathOrDefault(string? candidate, string fallback) =>
	!string.IsNullOrEmpty(candidate)
	&& candidate.StartsWith('/')
	&& !candidate.StartsWith("//")
	&& !candidate.StartsWith("/\\")
		? candidate
		: fallback;

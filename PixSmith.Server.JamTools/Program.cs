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

// How this deployment proves it is itself at the token endpoint. "PrivateKeyJwt" is the
// auth server's current recommendation: this app holds a private key, the server holds
// only the public half, and rotating is additive rather than a hard cutover. Set
// Oidc:ClientAuthentication to "ClientSecret" to fall back to the shared secret.
var usePrivateKeyJwt = !string.Equals(
	oidc["ClientAuthentication"], "ClientSecret", StringComparison.OrdinalIgnoreCase);

if (usePrivateKeyJwt)
{
	builder.Services.AddSingleton(sp => new ClientAssertionService(
		oidc["ClientId"] ?? throw new InvalidOperationException("Oidc:ClientId is required."),
		oidc["Authority"] ?? throw new InvalidOperationException("Oidc:Authority is required."),
		Path.Combine(builder.Environment.ContentRootPath,
			oidc["SigningKeyPath"] ?? "keys/client-signing-key.pem"),
		sp.GetRequiredService<ILogger<ClientAssertionService>>(),
		// Defaults to the issuer, which is what this auth server expects. Override only
		// for a server that wants its token endpoint URL instead.
		oidc["ClientAssertionAudience"]));
}

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

		// With an assertion there is no secret to configure at all — that is the point.
		if (!usePrivateKeyJwt)
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

		// ── Tenancy ───────────────────────────────────────────────────────────
		// The auth server nests application access inside a company: a user may use
		// this app when their company subscribes to it. Which company a token is for
		// is chosen at authorize time via an "organization" parameter — OpenIddict
		// passes unknown parameters through, and the authorize endpoint reads it.
		//
		// Leave Oidc:Organization empty to let the auth server decide: it resolves a
		// user with exactly one membership automatically, and prompts anyone with
		// several. Set it to pin this app to one company.
		var organization = oidc["Organization"];
		if (!string.IsNullOrWhiteSpace(organization))
		{
			options.Events.OnRedirectToIdentityProvider = context =>
			{
				context.ProtocolMessage.SetParameter("organization", organization);
				return Task.CompletedTask;
			};
		}

		// The OIDC handler has no first-class private_key_jwt support, so the assertion
		// is attached to the token request by hand. This is the only leg that needs it:
		// the authorize request identifies the client by client_id alone.
		if (usePrivateKeyJwt)
		{
			options.Events.OnAuthorizationCodeReceived = context =>
			{
				var assertions = context.HttpContext.RequestServices
					.GetRequiredService<ClientAssertionService>();

				context.TokenEndpointRequest!.ClientAssertionType =
					"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
				context.TokenEndpointRequest.ClientAssertion = assertions.CreateAssertion();
				context.TokenEndpointRequest.ClientSecret = null;

				return Task.CompletedTask;
			};
		}

		// Anything that goes wrong on the way back — the user cancelling, an expired
		// code, a clock skew — otherwise surfaces as an unhandled exception and a raw
		// 500 page. Send them back to the sign-in page instead; the detail is already
		// in the server log.
		options.Events.OnRemoteFailure = context =>
		{
			// access_denied is the tenancy answer: the person authenticated fine, but
			// their company has no subscription to this app (or their membership is
			// inactive). That deserves its own message — "try again" is wrong advice.
			var error = context.Failure?.Message.Contains("access_denied", StringComparison.OrdinalIgnoreCase) == true
				? "no_access"
				: "signin_failed";

			context.Response.Redirect($"/login?error={error}");
			context.HandleResponse();
			return Task.CompletedTask;
		};
	});

builder.Services.AddAuthorization();

var app = builder.Build();

// Construct the assertion service now rather than on first use. It generates the signing
// key and writes its public JWKS on construction, and both need to exist *before* a
// sign-in is attempted — provisioning registers that public key. Resolving it lazily meant
// a freshly cloned checkout had no key until something happened to touch it.
if (usePrivateKeyJwt)
{
	app.Services.GetRequiredService<ClientAssertionService>();
}

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

// The public half of this deployment's assertion key, in JWKS form — what the auth
// server needs to verify our assertions. Public keys only, so serving it is harmless;
// tools/provision-app-access.sh reads it from here rather than making anyone copy key
// material around by hand.
if (usePrivateKeyJwt)
{
	api.MapGet("/auth/client-jwks", (ClientAssertionService assertions) =>
		Results.Content(assertions.PublicJwks(), "application/json"));
}

// What the Success page reads. Answers for signed-out callers too, so the SPA can
// tell "not signed in" apart from "something broke".
api.MapGet("/auth/session", async (HttpContext context) =>
{
	var user = context.User;
	if (user.Identity?.IsAuthenticated != true)
		return Results.Ok(new { authenticated = false });

	var accessToken = await context.GetTokenAsync("access_token");
	var expiresAt = await context.GetTokenAsync("expires_at");

	// Emitted once the auth server reaches stage 4 of its multi-tenancy rollout;
	// null until then, so treat their absence as "no company context yet" rather
	// than an error.
	var orgId = user.FindFirst("org_id")?.Value;
	var orgSlug = user.FindFirst("org_slug")?.Value;

	return Results.Ok(new
	{
		authenticated = true,
		subject = user.FindFirst("sub")?.Value,
		name = user.Identity.Name ?? user.FindFirst("name")?.Value,
		email = user.FindFirst("email")?.Value,
		// Company-scoped under the tenant model: the platform-wide Admin role is
		// deliberately not carried into an application token.
		roles = user.FindAll("role").Select(c => c.Value).ToArray(),
		organization = orgId is null && orgSlug is null
			? null
			: new { id = orgId, slug = orgSlug },
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

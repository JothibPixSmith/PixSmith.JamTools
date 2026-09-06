using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;

namespace PixSmith.Server.JamTools.Authentication;

/// <summary>
/// Keeps the authentication ticket — which carries the OAuth tokens, because the
/// OpenID Connect handler is configured with SaveTokens — in this process's memory.
/// The browser only ever receives the key, so the access token never leaves the
/// server and is reachable solely through the caller's session cookie.
/// </summary>
/// <remarks>
/// In-memory means single-process and lost on restart: every session is signed out
/// when the host recycles. Swap the cache for Redis or a database to survive that,
/// or to run more than one instance.
/// </remarks>
public sealed class ServerSideTicketStore(IMemoryCache cache) : ITicketStore
{
	private const string KeyPrefix = "auth-ticket:";
	private static readonly TimeSpan FallbackLifetime = TimeSpan.FromHours(8);

	public Task<string> StoreAsync(AuthenticationTicket ticket)
	{
		var key = KeyPrefix + Guid.NewGuid().ToString("N");
		return RenewAsync(key, ticket).ContinueWith(_ => key, TaskScheduler.Current);
	}

	public Task RenewAsync(string key, AuthenticationTicket ticket)
	{
		var options = new MemoryCacheEntryOptions();

		// Outlive the token itself so a refresh can still happen on the next request.
		if (ticket.Properties.ExpiresUtc is { } expiresUtc)
			options.SetAbsoluteExpiration(expiresUtc);
		else
			options.SetSlidingExpiration(FallbackLifetime);

		cache.Set(key, ticket, options);
		return Task.CompletedTask;
	}

	public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
		Task.FromResult(cache.Get<AuthenticationTicket>(key));

	public Task RemoveAsync(string key)
	{
		cache.Remove(key);
		return Task.CompletedTask;
	}
}

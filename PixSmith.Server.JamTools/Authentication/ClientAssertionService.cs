using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PixSmith.Server.JamTools.Authentication;

/// <summary>
/// Authenticates this app to the auth server with a signed assertion
/// (<c>private_key_jwt</c>) instead of a shared secret.
/// </summary>
/// <remarks>
/// A shared secret has to exist somewhere readable — a config file, an environment
/// variable, a pipeline — and rotating it is a hard cutover because the server stores
/// exactly one value. With an assertion this deployment holds its own private key, the
/// server holds only the public half, and rolling a key is additive: publish both, move
/// the deployments, then drop the old one.
/// </remarks>
public sealed class ClientAssertionService
{
	private const string AssertionTokenType = "client-authentication+jwt";

	private readonly ECDsa _key;
	private readonly string _keyId;
	private readonly string _clientId;
	private readonly string _jwksPath;
	private readonly string _audience;

	public ClientAssertionService(
		string clientId, string authority, string keyPath,
		ILogger<ClientAssertionService> logger, string? audience = null)
	{
		_clientId = clientId;
		_key = LoadOrCreateKey(keyPath, logger);
		_keyId = ComputeKeyId(_key);
		_jwksPath = Path.ChangeExtension(keyPath, null) + ".jwks.json";

		// The audience is the ISSUER, as a single string. Verified against this server,
		// because none of it is guessable from the error text:
		//
		//   ["issuer", "token endpoint"]  → ID2171 "malformed or isn't of the expected
		//                                   type" — an array is refused outright, even
		//                                   though RFC 7523 permits one
		//   "…/connect/token"            → "the 'aud' claim doesn't match the expected
		//                                   value", despite OIDC Core saying the audience
		//                                   SHOULD be the token endpoint URL
		//   "http://host/"  (the issuer) → accepted
		var issuer = authority.TrimEnd('/') + "/";
		_audience = string.IsNullOrWhiteSpace(audience) ? issuer : audience;

		// Written beside the private key so provisioning can register the public half
		// without this app having to be running — it only has to have run once. Public
		// components only, so this file is not a secret.
		try
		{
			File.WriteAllText(_jwksPath, PublicJwks());
		}
		catch (Exception ex)
		{
			logger.LogWarning(ex, "Could not write the public JWKS to {Path}", _jwksPath);
		}
	}

	/// <summary>The public half, as a JWKS, for registering with the auth server.</summary>
	/// <remarks>
	/// Public components only — the auth server refuses a key set carrying private
	/// material outright rather than stripping it, which is the right call: it means
	/// nobody quietly registers a key set they have just compromised.
	/// </remarks>
	public string PublicJwks()
	{
		var p = _key.ExportParameters(includePrivateParameters: false);

		var jwk = new Dictionary<string, object>
		{
			["kty"] = "EC",
			["crv"] = "P-256",
			["x"] = Base64UrlEncoder.Encode(p.Q.X!),
			["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
			["use"] = "sig",          // the validator requires this exact value
			["alg"] = "ES256",
			["kid"] = _keyId,
		};

		return JsonSerializer.Serialize(new { keys = new[] { jwk } });
	}

	public string KeyId => _keyId;

	public string CreateAssertion()
	{
		var now = DateTime.UtcNow;

		var descriptor = new SecurityTokenDescriptor
		{
			// A plain "JWT" here is rejected with ID2089: OpenIddict enforces the
			// RFC 7523bis media type so a token minted for some other purpose cannot be
			// replayed as a client credential.
			TokenType = AssertionTokenType,
			Issuer = _clientId,
			IssuedAt = now,
			NotBefore = now,
			Expires = now.AddMinutes(2),
			Claims = new Dictionary<string, object>
			{
				["sub"] = _clientId,
				["jti"] = Guid.NewGuid().ToString("N"),
				["aud"] = _audience,
			},
			SigningCredentials = new SigningCredentials(
				new ECDsaSecurityKey(_key) { KeyId = _keyId },
				SecurityAlgorithms.EcdsaSha256),
		};

		return new JsonWebTokenHandler().CreateToken(descriptor);
	}

	private static ECDsa LoadOrCreateKey(string keyPath, ILogger logger)
	{
		var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

		if (File.Exists(keyPath))
		{
			key.ImportFromPem(File.ReadAllText(keyPath));
			logger.LogInformation("Client assertion key loaded from {Path}", keyPath);
			return key;
		}

		var directory = Path.GetDirectoryName(keyPath);
		if (!string.IsNullOrEmpty(directory))
			Directory.CreateDirectory(directory);

		File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());

		if (!OperatingSystem.IsWindows())
			File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

		logger.LogWarning(
			"No client assertion key at {Path} — generated a new one. Register its public half " +
			"with the auth server (tools/provision-app-access.sh) or token requests will fail.",
			keyPath);

		return key;
	}

	/// <summary>RFC 7638 thumbprint, so the kid is stable and derived from the key itself.</summary>
	private static string ComputeKeyId(ECDsa key)
	{
		var p = key.ExportParameters(includePrivateParameters: false);

		// Canonical form: the required members, lexicographically ordered, no whitespace.
		var canonical =
			$"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{Base64UrlEncoder.Encode(p.Q.X!)}\"," +
			$"\"y\":\"{Base64UrlEncoder.Encode(p.Q.Y!)}\"}}";

		return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
	}
}

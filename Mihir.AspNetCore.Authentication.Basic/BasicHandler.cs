using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Mihir.AspNetCore.Authentication.Basic
{
	public class BasicHandler : AuthenticationHandler<BasicOptions>
	{
		private readonly IBasicUserValidationService _basicUserValidationService;

		public BasicHandler(IOptionsMonitor<BasicOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IBasicUserValidationService basicUserValidationService) 
			: base(options, logger, encoder, clock)
		{
			_basicUserValidationService = basicUserValidationService;
		}

		//protected new BasicEvents Events { get => (BasicEvents)base.Events; set => base.Events = value; }
		//protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new BasicEvents());

		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
			{
				return AuthenticateResult.NoResult();
			}

			if (!AuthenticationHeaderValue.TryParse(Request.Headers[HeaderNames.Authorization], out var headerValue))
			{
				return AuthenticateResult.NoResult();
			}

			if (!headerValue.Scheme.Equals(BasicDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase))
			{
				return AuthenticateResult.NoResult();
			}

			var usernameAndPassword = Encoding.UTF8.GetString(Convert.FromBase64String(headerValue.Parameter));
			var usernameAndPasswordSplit = usernameAndPassword.Split(':');
			if (usernameAndPasswordSplit.Length != 2)
			{
				return AuthenticateResult.Fail("Invalid Basic authentication header");
			}
			var username = usernameAndPasswordSplit[0];
			var password = usernameAndPasswordSplit[1];

			var isValidUser = await _basicUserValidationService.IsValidAsync(username, password);
			if (!isValidUser)
			{
				return AuthenticateResult.Fail("Invalid username or password");
			}

			var claims = new[] { new Claim(ClaimTypes.Name, username) };
			var identity = new ClaimsIdentity(claims, Scheme.Name);
			var principal = new ClaimsPrincipal(identity);
			var ticket = new AuthenticationTicket(principal, Scheme.Name);
			return AuthenticateResult.Success(ticket);
		}

		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			Response.Headers[HeaderNames.WWWAuthenticate] = Options.Challenge;
			await base.HandleChallengeAsync(properties);
		}
	}
}

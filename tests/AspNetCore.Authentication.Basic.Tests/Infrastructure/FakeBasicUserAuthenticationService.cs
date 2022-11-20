// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Net.Http.Headers;
	using System.Security.Claims;
	using System.Text;
	using System.Threading.Tasks;

	internal class FakeBasicUserAuthenticationService : IBasicUserAuthenticationService
	{
		public Task<IBasicUser> AuthenticateAsync(string username, string password)
		{
			User user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(password, StringComparison.OrdinalIgnoreCase));
			if(user != null)
			{
				if(user.Password == FakeUsers.FakePasswordThrowsNotImplemented)
				{
					throw new NotImplementedException();
				}
#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

				if(user.Password == FakeUsers.FakePasswordIgnoreAuthenticationIfAllowAnonymous)
				{
					throw new InvalidOperationException(nameof(BasicOptions.IgnoreAuthenticationIfAllowAnonymous));
				}
#endif

				return Task.FromResult((IBasicUser)new FakeBasicUser(username));
			}

			return Task.FromResult((IBasicUser)null);
		}
	}

	internal class User
	{
		public User(string username, string password, IReadOnlyCollection<Claim> claims = null)
		{
			this.Username = username;
			this.Password = password;
			this.Claims = claims;
		}

		public string Username { get; }
		public string Password { get; }
		public IReadOnlyCollection<Claim> Claims { get; }

		public AuthenticationHeaderValue ToAuthenticationHeaderValue()
		{
			return new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, Convert.ToBase64String(Encoding.UTF8.GetBytes($"{this.Username}:{this.Password}")));
		}
	}

	internal class FakeBasicUser : IBasicUser
	{
		public FakeBasicUser(string userName)
		{
			this.UserName = userName;
		}

		public string UserName { get; set; }

		public IReadOnlyCollection<Claim> Claims { get; }
	}

	internal class FakeUsers
	{
		internal const string FakeUserName = "FakeUser";
		internal static string FakeInvalidPassword = "<invalid-password>";
		internal static string FakePassword = "myrandomfakepassword";
		internal static string FakePasswordThrowsNotImplemented = "myrandomfakepassowrd-not-implemented";
		internal static string FakePasswordIgnoreAuthenticationIfAllowAnonymous = "IgnoreAuthenticationIfAllowAnonymous";
		internal static string FakeUserOwner = "Fake Owner";
		internal static Claim FakeNameClaim = new Claim(ClaimTypes.Name, FakeUserName, ClaimValueTypes.String);
		internal static Claim FakeNameIdentifierClaim = new Claim(ClaimTypes.NameIdentifier, FakeUserName, ClaimValueTypes.String);
		internal static Claim FakeRoleClaim = new Claim(ClaimTypes.Role, "FakeRoleClaim", ClaimValueTypes.String);

		internal static User FakeUser => new User(FakeUserName, FakePassword, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim });
		internal static User FakeUserWithEmptyPassword => new User(FakeUserName, string.Empty, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim });
		internal static User FakeUserThrowsNotImplemented => new User(FakeUserName, FakePasswordThrowsNotImplemented, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim });
		internal static User FakeUserIgnoreAuthenticationIfAllowAnonymous => new User(FakeUserName, FakePasswordIgnoreAuthenticationIfAllowAnonymous, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim });

		internal static List<User> Users => new List<User>
		{
			FakeUser,
			FakeUserWithEmptyPassword,
			FakeUserThrowsNotImplemented,
			FakeUserIgnoreAuthenticationIfAllowAnonymous
		};
	}

	internal class FakeBasicUserAuthenticationServiceFactory : IBasicUserAuthenticationServiceFactory
	{
		/// <inheritdoc />
		public IBasicUserAuthenticationService CreateBasicUserAuthenticationService(string authenticationSchemaName)
		{
			return new FakeBasicUserAuthenticationService();
		}
	}
}

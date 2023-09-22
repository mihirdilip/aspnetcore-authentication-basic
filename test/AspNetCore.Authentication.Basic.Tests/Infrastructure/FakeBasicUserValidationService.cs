﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.Basic.Tests.Infrastructure
{
    class FakeBasicUserValidationService : IBasicUserValidationService
    {
        public Task<bool> IsValidAsync(string username, string password, CancellationToken cancellationToken)
        {
            var user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(password, StringComparison.OrdinalIgnoreCase));
            if (user != null)
            {
                if (user.Password == FakeUsers.FakePasswordThrowsNotImplemented)
                {
                    throw new NotImplementedException();
                }
#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
                else if (user.Password == FakeUsers.FakePasswordIgnoreAuthenticationIfAllowAnonymous)
                {
                    throw new InvalidOperationException(nameof(BasicOptions.IgnoreAuthenticationIfAllowAnonymous));
                }
#endif

                return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }
    }

    class User
    {
        public User(string username, string password, IReadOnlyCollection<Claim> claims = null)
        {
            Username = username;
            Password = password;
            Claims = claims;
        }
        public string Username { get; }
        public string Password { get; }
        public IReadOnlyCollection<Claim> Claims { get; }

        public AuthenticationHeaderValue ToAuthenticationHeaderValue()
        {
            return new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Username}:{Password}")));
        }
    }

    class FakeUsers
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
}

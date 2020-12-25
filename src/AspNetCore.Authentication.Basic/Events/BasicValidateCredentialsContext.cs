// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Context used for validating credentials.
    /// </summary>
    public class BasicValidateCredentialsContext : ResultContext<BasicOptions>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public BasicValidateCredentialsContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, string username, string password)
            : base(context, scheme, options)
        {
            Username = username;
            Password = password;
        }

        /// <summary>
        /// Gets the Username.
        /// </summary>
        public string Username { get; }

        /// <summary>
        /// Gets the Password.
        /// </summary>
        public string Password { get; }

        /// <summary>
        /// Calling this method will handle construction of authentication principal (<see cref="ClaimsPrincipal" />) from the user details 
        /// which will be assiged to the <see cref="ResultContext{TOptions}.Principal"/> property 
        /// and <see cref="ResultContext{TOptions}.Success"/> method will also be called.
        /// </summary>
        /// <param name="claims">Claims to be added to the identity.</param>
        public void ValidationSucceeded(IEnumerable<Claim> claims = null)
        {
            Principal = BasicUtils.BuildClaimsPrincipal(Username, Scheme.Name, Options.ClaimsIssuer, claims);
            Success();
        }

        /// <summary>
        /// If parameter <paramref name="failureMessage"/> passed is empty or null then NoResult() method is called 
        /// otherwise, <see cref="ResultContext{TOptions}.Fail(string)"/> method will be called.
        /// </summary>
        /// <param name="failureMessage">(Optional) The failure message.</param>
        public void ValidationFailed(string failureMessage = null)
        {
            if (string.IsNullOrWhiteSpace(failureMessage))
            {
                NoResult();
                return;
            }
            Fail(failureMessage);
        }

        /// <summary>
        /// Calling this method is same as calling <see cref="ResultContext{TOptions}.Fail(Exception)"/> method.
        /// </summary>
        /// <param name="failureException">The failure exception.</param>
        public void ValidationFailed(Exception failureException)
        {
            Fail(failureException);
        }
    }
}

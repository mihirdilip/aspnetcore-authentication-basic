// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

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
        /// Call this method at the end after credentials are validated and are valid.
        /// NOTE: This call will be igoned if <see cref="ResultContext{TOptions}.Principal"/> is already set or, 
        /// any of these methods is called <see cref="ResultContext{TOptions}.NoResult"/>, <see cref="ResultContext{TOptions}.Success"/>, <see cref="ResultContext{TOptions}.Fail(string)"/>, <see cref="ResultContext{TOptions}.Fail(Exception)"/>
        /// </summary>
        public void ValidationSucceeded()
        {
            if (Principal != null && Result != null)
            {
                ValidationResult = true;
            }
        }

        /// <summary>
        /// Call this method at the end after credentials are validated and are not valid.
        /// NOTE: This call will be igoned if <see cref="ResultContext{TOptions}.Principal"/> is already set or, 
        /// any of these methods is called <see cref="ResultContext{TOptions}.NoResult"/>, <see cref="ResultContext{TOptions}.Success"/>, <see cref="ResultContext{TOptions}.Fail(string)"/>, <see cref="ResultContext{TOptions}.Fail(Exception)"/>
        /// </summary>
        /// <param name="failureMessage">The failure message.</param>
        public void ValidationFailed(string failureMessage = null) 
        {
            ValidationFailed(
                string.IsNullOrWhiteSpace(failureMessage) 
                    ? null 
                    : new Exception(failureMessage)
            );
        }

        /// <summary>
        /// Call this method at the end after credentials are validated and are not valid.
        /// NOTE: This call will be igoned if <see cref="ResultContext{TOptions}.Principal"/> is already set or, 
        /// any of these methods is called <see cref="ResultContext{TOptions}.NoResult"/>, <see cref="ResultContext{TOptions}.Success"/>, <see cref="ResultContext{TOptions}.Fail(string)"/>, <see cref="ResultContext{TOptions}.Fail(Exception)"/>
        /// </summary>
        /// <param name="failureException">The failure exception.</param>
        public void ValidationFailed(Exception failureException)
        {
            if (Principal != null && Result != null)
            {
                ValidationResult = false;
                ValidationFailureException = failureException;
            }
        }

        internal bool? ValidationResult { get; private set; }
        internal Exception ValidationFailureException { get; private set; }
    }
}

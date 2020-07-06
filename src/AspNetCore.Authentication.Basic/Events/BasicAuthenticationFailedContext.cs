// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Context used when authentication is failed.
    /// </summary>
    public class BasicAuthenticationFailedContext : ResultContext<BasicOptions>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="exception"></param>
        public BasicAuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, Exception exception)
            : base(context, scheme, options)
        {
            Exception = exception;
        }

        /// <summary>
        /// The Exception thrown when authenticating.
        /// </summary>
        public Exception Exception { get; }
    }
}

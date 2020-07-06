// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Context used when authentication is succeeded.
    /// </summary>
    public class BasicAuthenticationSucceededContext : ResultContext<BasicOptions>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="principal"></param>
        public BasicAuthenticationSucceededContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, ClaimsPrincipal principal)
            : base(context, scheme, options)
        {
            base.Principal = principal;
        }

        /// <summary>
        /// Get the <see cref="ClaimsPrincipal"/> containing the user claims.
        /// </summary>
        public new ClaimsPrincipal Principal => base.Principal;
    }
}

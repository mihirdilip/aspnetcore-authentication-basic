// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Utility class.
	/// </summary>
	internal static class BasicUtils
	{
		/// <summary>
		/// Builds Claims Principal from the provided information. 
		/// If the <paramref name="claims"/> does not have claim of type <see cref="ClaimTypes.NameIdentifier"/> then username will be added as claim of type <see cref="ClaimTypes.NameIdentifier"/>.
		/// If the <paramref name="claims"/> does not have claim of type <see cref="ClaimTypes.Name"/> then username will be added as claim of type <see cref="ClaimTypes.Name"/>.
		/// </summary>
		/// <param name="username">The username.</param>
		/// <param name="schemeName">The scheme name.</param>
		/// <param name="claimsIssuer">The claims issuer.</param>
		/// <param name="claims">The list of claims.</param>
		/// <returns></returns>
		internal static ClaimsPrincipal BuildClaimsPrincipal(string username, string schemeName, string claimsIssuer, IEnumerable<Claim> claims = null)
		{
			if (string.IsNullOrWhiteSpace(schemeName)) throw new ArgumentNullException(nameof(schemeName));

			var claimsList = new List<Claim>();
			if (claims != null) claimsList.AddRange(claims);

			if (!string.IsNullOrWhiteSpace(username))
			{
				if (!claimsList.Any(c => c.Type == ClaimTypes.NameIdentifier))
				{
					claimsList.Add(new Claim(ClaimTypes.NameIdentifier, username, ClaimValueTypes.String, claimsIssuer));
				}

				if (!claimsList.Any(c => c.Type == ClaimTypes.Name))
				{
					claimsList.Add(new Claim(ClaimTypes.Name, username, ClaimValueTypes.String, claimsIssuer));
				}
			}

			return new ClaimsPrincipal(new ClaimsIdentity(claimsList, schemeName));
		}
	}
}

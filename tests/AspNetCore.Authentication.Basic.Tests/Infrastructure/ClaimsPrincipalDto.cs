// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Security.Claims;
	using System.Security.Principal;

	[Serializable]
	internal struct ClaimsPrincipalDto
	{
		public ClaimsPrincipalDto(ClaimsPrincipal user)
		{
			this.Identity = new ClaimsIdentityDto(user.Identity);
			this.Identities = user.Identities.Select(i => new ClaimsIdentityDto(i));
			this.Claims = user.Claims.Select(c => new ClaimDto(c));
		}

		public ClaimsIdentityDto Identity { get; set; }
		public IEnumerable<ClaimsIdentityDto> Identities { get; private set; }
		public IEnumerable<ClaimDto> Claims { get; set; }
	}

	[Serializable]
	internal struct ClaimsIdentityDto
	{
		public ClaimsIdentityDto(IIdentity identity)
		{
			this.Name = identity.Name;
			this.IsAuthenticated = identity.IsAuthenticated;
			this.AuthenticationType = identity.AuthenticationType;
		}

		public string Name { get; set; }
		public bool IsAuthenticated { get; set; }
		public string AuthenticationType { get; set; }
	}

	[Serializable]
	internal struct ClaimDto
	{
		public ClaimDto(Claim claim)
		{
			this.Type = claim.Type;
			this.Value = claim.Value;
			this.Issuer = claim.Issuer;
			this.OriginalIssuer = claim.OriginalIssuer;
		}

		public string Type { get; set; }
		public string Value { get; set; }
		public string Issuer { get; set; }
		public string OriginalIssuer { get; set; }
	}
}

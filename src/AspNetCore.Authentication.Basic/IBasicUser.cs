// Copyright (c) Matthias Gernand. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic
{
	using System.Collections.Generic;
	using System.Security.Claims;

	/// <summary>
	///     Basic user details.
	/// </summary>
	public interface IBasicUser
	{
		/// <summary>
		///     The user name of the basic login.
		/// </summary>
		string UserName { get; }

		/// <summary>
		///     Optional list of claims to be sent back with the authentication request.
		/// </summary>
		IReadOnlyCollection<Claim> Claims { get; }
	}
}

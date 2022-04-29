// Copyright (c) Mihir Dilip, Matthias Gernand. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Implementation of this interface will be used by the 'Basic' authentication handler to validated the username and password.
	/// </summary>
	public interface IBasicUserAuthenticationService
	{
		/// <summary>
		/// Authenticates the username &amp; password  and returns an instance of <see cref="IBasicUser"/> if successful.
		/// </summary>
		/// <param name="username"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		Task<IBasicUser> AuthenticateAsync(string username, string password);
	}
}

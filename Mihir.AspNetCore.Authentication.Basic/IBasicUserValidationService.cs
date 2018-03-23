// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Implemention of this interface will be used by the 'Basic' authentication handler to validated the username and password.
	/// </summary>
	public interface IBasicUserValidationService
	{
		/// <summary>
		/// Implementation of the username & password validation logic.
		/// </summary>
		/// <param name="username"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		Task<bool> IsValidAsync(string username, string password);
	}
}

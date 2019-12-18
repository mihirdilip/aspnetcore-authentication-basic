// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Default values used by basic authentication.
	/// </summary>
	[Obsolete("This NuGet package has been made obsolete and moved to a new package named 'AspNetCore.Authentication.Basic'. Please consider removing this package and download the new one as there will be no future updates on this package. Sorry for the inconvenience caused. This was done purely for the naming of the package. New package name is 'AspNetCore.Authentication.Basic' which can be downloaded using NuGet Package Manager or from https://www.nuget.org/packages/AspNetCore.Authentication.Basic.")]
	public static class BasicDefaults
	{
		/// <summary>
		/// Default value for AuthenticationScheme 
		/// </summary>
		public const string AuthenticationScheme = "Basic";
	}
}

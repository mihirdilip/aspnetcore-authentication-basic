// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.Options;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// This post configure options checks whether the required option property <see cref="BasicOptions.Realm" /> is set or not on <see cref="BasicOptions"/>.
	/// </summary>
	[Obsolete("This NuGet package has been made obsolete and moved to a new package named 'AspNetCore.Authentication.Basic'. Please consider removing this package and download the new one as there will be no future updates on this package. Sorry for the inconvenience caused. This was done purely for the naming of the package. New package name is 'AspNetCore.Authentication.Basic' which can be downloaded using NuGet Package Manager or from https://www.nuget.org/packages/AspNetCore.Authentication.Basic.")]
	class BasicPostConfigureOptions : IPostConfigureOptions<BasicOptions>
	{
		public void PostConfigure(string name, BasicOptions options)
		{
			if (string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException("Realm must be set in basic options");
			}
		}
	}
}

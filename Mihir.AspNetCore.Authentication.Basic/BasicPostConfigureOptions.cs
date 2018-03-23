// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.Options;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// This post configure options checks whether the required option property <see cref="BasicOptions.Realm" /> is set or not on <see cref="BasicOptions"/>.
	/// </summary>
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

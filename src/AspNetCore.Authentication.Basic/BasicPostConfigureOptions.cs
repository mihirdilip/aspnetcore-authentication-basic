// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// This post configure options checks whether the required option property <see cref="BasicOptions.Realm" /> is set or not on <see cref="BasicOptions"/>.
	/// </summary>
	internal class BasicPostConfigureOptions : IPostConfigureOptions<BasicOptions>
	{
		public void PostConfigure(string name, BasicOptions options)
		{
			if (!options.SuppressWWWAuthenticateHeader && string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException($"{nameof(BasicOptions.Realm)} must be set in {typeof(BasicOptions).Name} when setting up the authentication.");
			}

			if (options.Events?.OnValidateCredentials == null && options.EventsType == null && options.BasicUserValidationServiceType == null)
			{
				throw new InvalidOperationException($"Either {nameof(BasicOptions.Events.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extention method with type parameter of type {nameof(IBasicUserValidationService)}.");
			}
		}
	}
}

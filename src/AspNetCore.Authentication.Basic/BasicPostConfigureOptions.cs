// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.Authentication.Basic
{
	using Microsoft.Extensions.DependencyInjection;

	/// <summary>
	/// This post configure options checks whether the required option property <see cref="BasicOptions.Realm" /> is set or not on <see cref="BasicOptions"/>.
	/// </summary>
	internal class BasicPostConfigureOptions : IPostConfigureOptions<BasicOptions>
	{
		private readonly IServiceProvider serviceProvider;

		public BasicPostConfigureOptions(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		public void PostConfigure(string name, BasicOptions options)
		{
			if (!options.SuppressWWWAuthenticateHeader && string.IsNullOrWhiteSpace(options.Realm))
			{
				throw new InvalidOperationException($"{nameof(BasicOptions.Realm)} must be set in {nameof(BasicOptions)} when setting up the authentication.");
			}

			IBasicUserAuthenticationServiceFactory basicUserAuthenticationServiceFactory = this.serviceProvider.GetService<IBasicUserAuthenticationServiceFactory>();
			if (options.Events?.OnValidateCredentials == null && options.EventsType == null && options.BasicUserValidationServiceType == null && basicUserAuthenticationServiceFactory == null)
			{
				throw new InvalidOperationException($"Either {nameof(BasicOptions.Events.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.");
			}
		}
	}
}

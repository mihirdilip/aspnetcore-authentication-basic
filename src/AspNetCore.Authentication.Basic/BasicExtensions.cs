// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Extension methods for basic authentication.
	/// </summary>
	public static class BasicExtensions
	{
		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">Sets the <see cref="BasicOptions"/>. Realm option property must be set.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions)
			where TBasicUserValidationService : class, IBasicUserValidationService
		{
			// Adds implementation of IBasicUserValidationService to the dependency container.
			builder.Services.AddTransient<IBasicUserValidationService, TBasicUserValidationService>();
			
			// Adds post configure options to the pipeline.
			builder.Services.AddSingleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>();

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(BasicDefaults.AuthenticationScheme, configureOptions);
		}
	}
}

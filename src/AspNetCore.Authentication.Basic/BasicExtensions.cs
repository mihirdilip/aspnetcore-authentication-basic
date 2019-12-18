// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace Mihir.AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Extension methods for basic authentication.
	/// </summary>
	[Obsolete("This NuGet package has been made obsolete and moved to a new package named 'AspNetCore.Authentication.Basic'. Please consider removing this package and download the new one as there will be no future updates on this package. Sorry for the inconvenience caused. This was done purely for the naming of the package. New package name is 'AspNetCore.Authentication.Basic' which can be downloaded using NuGet Package Manager or from https://www.nuget.org/packages/AspNetCore.Authentication.Basic.")]
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
			// Adds post configure options to the pipeline.
			builder.Services.AddSingleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>();

			// Adds implementation of IBasicUserValidationService to the dependency container.
			builder.Services.AddTransient<IBasicUserValidationService, TBasicUserValidationService>();

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(BasicDefaults.AuthenticationScheme, configureOptions);
		}
	}
}

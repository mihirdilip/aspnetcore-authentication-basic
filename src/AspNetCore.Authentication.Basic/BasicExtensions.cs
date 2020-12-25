// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
		/// Adds basic authentication scheme to the project. 
		/// <see cref="BasicEvents.OnValidateCredentials"/> delegate must be set on the <see cref="BasicOptions.Events"/>.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder)
			=> builder.AddBasic(BasicDefaults.AuthenticationScheme);

		/// <summary>
		/// Adds basic authentication scheme to the project. 
		/// <see cref="BasicEvents.OnValidateCredentials"/> delegate must be set on the <see cref="BasicOptions.Events"/>.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme)
			=> builder.AddBasic(authenticationScheme, configureOptions: null);

		/// <summary>
		/// Adds basic authentication scheme to the project. 
		/// <see cref="BasicEvents.OnValidateCredentials"/> delegate must be set on the Events property on <paramref name="configureOptions"/>.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions)
			=> builder.AddBasic(BasicDefaults.AuthenticationScheme, configureOptions);

		/// <summary>
		/// Adds basic authentication scheme to the project. 
		/// <see cref="BasicEvents.OnValidateCredentials"/> delegate must be set on the Events property on <paramref name="configureOptions"/>.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicOptions> configureOptions)
			=> builder.AddBasic(authenticationScheme, displayName: null, configureOptions: configureOptions);

		/// <summary>
		/// Adds basic authentication scheme to the project. 
		/// <see cref="BasicEvents.OnValidateCredentials"/> delegate must be set on the Events property on <paramref name="configureOptions"/>.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The configure options.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<BasicOptions> configureOptions)
		{
			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>());

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(authenticationScheme, displayName, configureOptions);
		}







		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// If <see cref="BasicEvents.OnValidateCredentials"/> delegate is set on the <see cref="BasicOptions.Events"/> then it will be used instead of implementation of <see cref="IBasicUserValidationService"/>.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder) where TBasicUserValidationService : class, IBasicUserValidationService
			=> builder.AddBasic<TBasicUserValidationService>(BasicDefaults.AuthenticationScheme);

		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// If <see cref="BasicEvents.OnValidateCredentials"/> delegate is set on the <see cref="BasicOptions.Events"/> then it will be used instead of implementation of <see cref="IBasicUserValidationService"/>.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme) where TBasicUserValidationService : class, IBasicUserValidationService
			=> builder.AddBasic<TBasicUserValidationService>(authenticationScheme, configureOptions: null);

		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// If <see cref="BasicEvents.OnValidateCredentials"/> delegate is set on the Events property on <paramref name="configureOptions"/> then it will be used instead of implementation of <see cref="IBasicUserValidationService"/>.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <param name="configureOptions">The <see cref="BasicOptions"/>.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions) where TBasicUserValidationService : class, IBasicUserValidationService
			=> builder.AddBasic<TBasicUserValidationService>(BasicDefaults.AuthenticationScheme, configureOptions);

		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// If <see cref="BasicEvents.OnValidateCredentials"/> delegate is set on the Events property on <paramref name="configureOptions"/> then it will be used instead of implementation of <see cref="IBasicUserValidationService"/>.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="configureOptions">The <see cref="BasicOptions"/>.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicOptions> configureOptions) where TBasicUserValidationService : class, IBasicUserValidationService
			=> builder.AddBasic<TBasicUserValidationService>(authenticationScheme, displayName: null, configureOptions: configureOptions);

		/// <summary>
		/// Adds basic authentication scheme to the project. It takes a implementation of <see cref="IBasicUserValidationService"/> as type parameter.
		/// If <see cref="BasicEvents.OnValidateCredentials"/> delegate is set on the Events property on <paramref name="configureOptions"/> then it will be used instead of implementation of <see cref="IBasicUserValidationService"/>.
		/// </summary>
		/// <typeparam name="TBasicUserValidationService"></typeparam>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme">The authentication scheme.</param>
		/// <param name="displayName">The display name.</param>
		/// <param name="configureOptions">The <see cref="BasicOptions"/>.</param>
		/// <returns>The instance of <see cref="AuthenticationBuilder"/></returns>
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<BasicOptions> configureOptions)
			where TBasicUserValidationService : class, IBasicUserValidationService
		{
			// Adds implementation of IBasicUserValidationService to the dependency container.
			builder.Services.AddTransient<IBasicUserValidationService, TBasicUserValidationService>();
			builder.Services.Configure<BasicOptions>(
				authenticationScheme,
				o => o.BasicUserValidationServiceType = typeof(TBasicUserValidationService)
			);

			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>());

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(authenticationScheme, displayName, configureOptions);
		}
	}
}

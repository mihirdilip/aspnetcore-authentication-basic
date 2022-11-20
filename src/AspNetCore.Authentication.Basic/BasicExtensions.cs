// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic
{
	using System;
	using MadEyeMatt.AspNetCore.Authentication.Basic.Events;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.DependencyInjection.Extensions;
	using Microsoft.Extensions.Options;

	/// <summary>
	///     Extension methods for basic authentication.
	/// </summary>
	public static class BasicExtensions
	{
		/// <summary>
		///     Adds basic authentication scheme to the project.
		///     <see cref="BasicEvents.OnValidateCredentials" /> delegate must be set on the
		///     <see cref="BasicOptions.Events" />.
		/// </summary>
		/// <param name="builder"></param>
		/// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
		public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder)
		{
			return builder.AddBasic(BasicDefaults.AuthenticationScheme);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project.
        ///     <see cref="BasicEvents.OnValidateCredentials" /> delegate must be set on the
        ///     <see cref="BasicOptions.Events" />.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme)
		{
			return builder.AddBasic(authenticationScheme, null);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project.
        ///     <see cref="BasicEvents.OnValidateCredentials" /> delegate must be set on the Events property on
        ///     <paramref name="configureOptions" />.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions)
		{
			return builder.AddBasic(BasicDefaults.AuthenticationScheme, configureOptions);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project.
        ///     <see cref="BasicEvents.OnValidateCredentials" /> delegate must be set on the Events property on
        ///     <paramref name="configureOptions" />.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicOptions> configureOptions)
		{
			return builder.AddBasic(authenticationScheme, null, configureOptions);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project.
        ///     <see cref="BasicEvents.OnValidateCredentials" /> delegate must be set on the Events property on
        ///     <paramref name="configureOptions" />.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<BasicOptions> configureOptions)
		{
			// Add the authentication scheme name for the specific options.
			builder.Services.Configure<BasicOptions>(
				authenticationScheme,
				o => o.AuthenticationSchemeName = authenticationScheme);

			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>());

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(authenticationScheme, displayName, configureOptions);
		}


        /// <summary>
        ///     Adds basic authentication scheme to the project. It takes a implementation of
        ///     <see cref="IBasicUserAuthenticationService" /> as type parameter.
        ///     If <see cref="BasicEvents.OnValidateCredentials" /> delegate is set on the
        ///     <see cref="BasicOptions.Events" /> then it will be used instead of implementation of
        ///     <see cref="IBasicUserAuthenticationService" />.
        /// </summary>
        /// <typeparam name="TBasicUserValidationService"></typeparam>
        /// <param name="builder"></param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder) where TBasicUserValidationService : class, IBasicUserAuthenticationService
		{
			return builder.AddBasic<TBasicUserValidationService>(BasicDefaults.AuthenticationScheme);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project. It takes a implementation of
        ///     <see cref="IBasicUserAuthenticationService" /> as type parameter.
        ///     If <see cref="BasicEvents.OnValidateCredentials" /> delegate is set on the
        ///     <see cref="BasicOptions.Events" /> then it will be used instead of implementation of
        ///     <see cref="IBasicUserAuthenticationService" />.
        /// </summary>
        /// <typeparam name="TBasicUserValidationService"></typeparam>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme) where TBasicUserValidationService : class, IBasicUserAuthenticationService
		{
			return builder.AddBasic<TBasicUserValidationService>(authenticationScheme, null);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project. It takes a implementation of
        ///     <see cref="IBasicUserAuthenticationService" /> as type parameter.
        ///     If <see cref="BasicEvents.OnValidateCredentials" /> delegate is set on the Events property on
        ///     <paramref name="configureOptions" /> then it will be used instead of implementation of
        ///     <see cref="IBasicUserAuthenticationService" />.
        /// </summary>
        /// <typeparam name="TBasicUserValidationService"></typeparam>
        /// <param name="builder"></param>
        /// <param name="configureOptions">The <see cref="BasicOptions" />.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions) where TBasicUserValidationService : class, IBasicUserAuthenticationService
		{
			return builder.AddBasic<TBasicUserValidationService>(BasicDefaults.AuthenticationScheme, configureOptions);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project. It takes a implementation of
        ///     <see cref="IBasicUserAuthenticationService" /> as type parameter.
        ///     If <see cref="BasicEvents.OnValidateCredentials" /> delegate is set on the Events property on
        ///     <paramref name="configureOptions" /> then it will be used instead of implementation of
        ///     <see cref="IBasicUserAuthenticationService" />.
        /// </summary>
        /// <typeparam name="TBasicUserValidationService"></typeparam>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The <see cref="BasicOptions" />.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicOptions> configureOptions) where TBasicUserValidationService : class, IBasicUserAuthenticationService
		{
			return builder.AddBasic<TBasicUserValidationService>(authenticationScheme, null, configureOptions);
		}

        /// <summary>
        ///     Adds basic authentication scheme to the project. It takes a implementation of
        ///     <see cref="IBasicUserAuthenticationService" /> as type parameter.
        ///     If <see cref="BasicEvents.OnValidateCredentials" /> delegate is set on the Events property on
        ///     <paramref name="configureOptions" /> then it will be used instead of implementation of
        ///     <see cref="IBasicUserAuthenticationService" />.
        /// </summary>
        /// <typeparam name="TBasicUserValidationService"></typeparam>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The <see cref="BasicOptions" />.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder" /></returns>
        public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<BasicOptions> configureOptions)
			where TBasicUserValidationService : class, IBasicUserAuthenticationService
		{
			// Adds implementation of IBasicUserValidationService to the dependency container.
			builder.Services.AddTransient<IBasicUserAuthenticationService, TBasicUserValidationService>();

			// Add the authentication scheme name for the specific options.
			builder.Services.Configure<BasicOptions>(
				authenticationScheme,
				o =>
				{
					o.AuthenticationSchemeName = authenticationScheme;
					o.BasicUserValidationServiceType = typeof(TBasicUserValidationService);
				});

			// Adds post configure options to the pipeline.
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>());

			// Adds basic authentication scheme to the pipeline.
			return builder.AddScheme<BasicOptions, BasicHandler>(authenticationScheme, displayName, configureOptions);
		}
	}
}

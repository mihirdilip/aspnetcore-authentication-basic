using Microsoft.AspNetCore.Authentication;
using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Mihir.AspNetCore.Authentication.Basic
{
	public static class BasicExtensions
	{
		public static AuthenticationBuilder AddBasic<TBasicUserValidationService>(this AuthenticationBuilder builder, Action<BasicOptions> configureOptions)
			where TBasicUserValidationService : class, IBasicUserValidationService
		{
			builder.Services.AddSingleton<IPostConfigureOptions<BasicOptions>, BasicPostConfigureOptions>();
			builder.Services.AddTransient<IBasicUserValidationService, TBasicUserValidationService>();

			return builder.AddScheme<BasicOptions, BasicHandler>(BasicDefaults.AuthenticationScheme, configureOptions);
		}
	}
}

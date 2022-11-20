// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.DependencyInjection;
	using Xunit;

	public class BasicExtensionsTests
	{
		private Task<AuthenticationScheme> GetSchemeAsync(Action<AuthenticationBuilder> authenticationBuilderAction, string schemeName = BasicDefaults.AuthenticationScheme)
		{
			ServiceCollection services = new ServiceCollection();
			authenticationBuilderAction(services.AddAuthentication());
			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			return schemeProvider.GetSchemeAsync(schemeName);
		}

		private class MockUserAuthenticationService : IBasicUserAuthenticationService
		{
			public Task<IBasicUser> AuthenticateAsync(string username, string password)
			{
				throw new NotImplementedException();
			}
		}

		private class MockUserAuthenticationService2 : IBasicUserAuthenticationService
		{
			public Task<IBasicUser> AuthenticateAsync(string username, string password)
			{
				throw new NotImplementedException();
			}
		}

		[Fact]
		public void AddBasic_allows_chaining_default()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic());
		}

		[Fact]
		public void AddBasic_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(_ =>
			{
			}));
		}

		[Fact]
		public void AddBasic_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty));
		}

		[Fact]
		public void AddBasic_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddBasic_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddBasic_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddBasic()
				.AddBasic(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(BasicDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(BasicHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(BasicDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}


		[Fact]
		public void AddBasic_TBasicUserValidationService_allows_chaining()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserAuthenticationService>());
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserAuthenticationService>(_ =>
			{
			}));
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserAuthenticationService>(string.Empty));
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserAuthenticationService>(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserAuthenticationService>(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddBasic_TBasicUserValidationService_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddBasic<MockUserAuthenticationService>()
				.AddBasic<MockUserAuthenticationService>(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(BasicDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(BasicHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(BasicDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_does_not_replace_previously_user_registered_IBasicUserValidationService()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddSingleton<IBasicUserAuthenticationService, MockUserAuthenticationService2>();
			services.AddAuthentication()
				.AddBasic<MockUserAuthenticationService>();

			IEnumerable<ServiceDescriptor> serviceDescriptors = services.Where(s => s.ServiceType == typeof(IBasicUserAuthenticationService));
			Assert.Equal(2, serviceDescriptors.Count());

			ServiceDescriptor serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockUserAuthenticationService)));
			Assert.Equal(typeof(IBasicUserAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockUserAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockUserAuthenticationService2)));
			Assert.Equal(typeof(IBasicUserAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockUserAuthenticationService2), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
		}

		[Fact]
		public void AddBasic_TBasicUserValidationService_IBasicUserValidationService_is_registered_as_transient()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddBasic<MockUserAuthenticationService>();

			ServiceDescriptor serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IBasicUserAuthenticationService)));
			Assert.Equal(typeof(IBasicUserAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockUserAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			ServiceProvider sp = services.BuildServiceProvider();
			IBasicUserAuthenticationService provider = sp.GetService<IBasicUserAuthenticationService>();

			Assert.NotNull(provider);
			Assert.Equal(typeof(MockUserAuthenticationService), provider.GetType());
		}


		[Fact]
		public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic<MockUserAuthenticationService>());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic<MockUserAuthenticationService>(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic<MockUserAuthenticationService>(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic<MockUserAuthenticationService>(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic<MockUserAuthenticationService>(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddBasic_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddBasic_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddBasic_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddBasic_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddBasic_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddBasic(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(BasicHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}
	}
}

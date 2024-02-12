// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests
{
    public class BasicExtensionsTests
    {
        #region Verify Auth Scheme

        [Fact]
        public async Task AddBasic_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddBasic());
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddBasic_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddBasic(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddBasic_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddBasic(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddBasic_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddBasic(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddBasic_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddBasic(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }


        [Fact]
        public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_default()
        {
            var scheme = await GetSchemeAsync(a => a.AddBasic<MockUserValidationService>(), BasicDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddBasic<MockUserValidationService>(schemeName), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_configureOptions()
        {
            var scheme = await GetSchemeAsync(a => a.AddBasic<MockUserValidationService>(_ => { }));
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var scheme = await GetSchemeAsync(a => a.AddBasic<MockUserValidationService>(schemeName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddBasic_TBasicUserValidationService_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";
            var scheme = await GetSchemeAsync(a => a.AddBasic<MockUserValidationService>(schemeName, displayName, _ => { }), schemeName);
            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Verify Auth Scheme

        #region Allows Multiple Schemes

        [Fact]
        public async Task AddBasic_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddBasic()
                .AddBasic(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(BasicDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(typeof(BasicHandler).Name, defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(BasicDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        [Fact]
        public async Task AddBasic_TBasicUserValidationService_allows_multiple_schemes()
        {
            var schemeName = "CustomScheme";
            var displayName = "DisplayName";

            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddBasic<MockUserValidationService>()
                .AddBasic<MockUserValidationService>(schemeName, displayName, _ => { });

            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var defaultScheme = await schemeProvider.GetSchemeAsync(BasicDefaults.AuthenticationScheme);
            var scheme = await schemeProvider.GetSchemeAsync(schemeName);

            Assert.NotNull(defaultScheme);
            Assert.Equal(typeof(BasicHandler).Name, defaultScheme.HandlerType.Name);
            Assert.Null(defaultScheme.DisplayName);
            Assert.Equal(BasicDefaults.AuthenticationScheme, defaultScheme.Name);

            Assert.NotNull(scheme);
            Assert.Equal(typeof(BasicHandler).Name, scheme.HandlerType.Name);
            Assert.NotNull(scheme.DisplayName);
            Assert.Equal(displayName, scheme.DisplayName);
            Assert.Equal(schemeName, scheme.Name);
        }

        #endregion  // Allows Multiple Schemes

        #region TBasicUserValidationService tests

        [Fact]
        public void AddBasic_TBasicUserValidationService_IBasicUserValidationService_is_registered_as_transient()
        {
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddBasic<MockUserValidationService>();

            var serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IBasicUserValidationService)));
            Assert.Equal(typeof(IBasicUserValidationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockUserValidationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            var sp = services.BuildServiceProvider();
            var provider = sp.GetService<IBasicUserValidationService>();

            Assert.NotNull(provider);
            Assert.Equal(typeof(MockUserValidationService), provider.GetType());
        }

        [Fact]
        public void AddBasic_TBasicUserValidationService_does_not_replace_previously_user_registered_IBasicUserValidationService()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IBasicUserValidationService, MockUserValidationService2>();
            services.AddAuthentication()
                .AddBasic<MockUserValidationService>();

            var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IBasicUserValidationService));
            Assert.Equal(2, serviceDescriptors.Count());

            var serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockUserValidationService)));
            Assert.Equal(typeof(IBasicUserValidationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockUserValidationService), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

            serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockUserValidationService2)));
            Assert.Equal(typeof(IBasicUserValidationService), serviceDescriptor.ServiceType);
            Assert.Equal(typeof(MockUserValidationService2), serviceDescriptor.ImplementationType);
            Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
        }

        #endregion  // TBasicUserValidationService tests

        #region Allows chaining

        [Fact]
        public void AddBasic_allows_chaining_default()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic());
        }

        [Fact]
        public void AddBasic_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty));
        }

        [Fact]
        public void AddBasic_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(_ => { }));
        }

        [Fact]
        public void AddBasic_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty, _ => { }));
        }

        [Fact]
        public void AddBasic_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic(string.Empty, string.Empty, _ => { }));
        }


        [Fact]
        public void AddBasic_TBasicUserValidationService_allows_chaining()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserValidationService>());
        }

        [Fact]
        public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserValidationService>(string.Empty));
        }

        [Fact]
        public void AddBasic_TBasicUserValidationService_allows_chaining_with_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserValidationService>(_ => { }));
        }

        [Fact]
        public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserValidationService>(string.Empty, _ => { }));
        }

        [Fact]
        public void AddBasic_TBasicUserValidationService_allows_chaining_with_scheme_displayName_and_configureOptions()
        {
            var authenticationBuilder = new ServiceCollection().AddAuthentication();
            Assert.Same(authenticationBuilder, authenticationBuilder.AddBasic<MockUserValidationService>(string.Empty, string.Empty, _ => { }));
        }

        #endregion // Allows chaining

        private static Task<AuthenticationScheme?> GetSchemeAsync(Action<AuthenticationBuilder> authenticationBuilderAction, string schemeName = BasicDefaults.AuthenticationScheme)
        {
            var services = new ServiceCollection();
            authenticationBuilderAction(services.AddAuthentication());
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            return schemeProvider.GetSchemeAsync(schemeName);
        }

        private class MockUserValidationService : IBasicUserValidationService
        {
            public Task<bool> IsValidAsync(string username, string password)
            {
                throw new NotImplementedException();
            }
        }

        private class MockUserValidationService2 : IBasicUserValidationService
        {
            public Task<bool> IsValidAsync(string username, string password)
            {
                throw new NotImplementedException();
            }
        }
    }
}

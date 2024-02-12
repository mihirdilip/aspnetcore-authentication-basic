// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using AspNetCore.Authentication.Basic.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests
{
    public class BasicOptionsTests
    {
        [Fact]
        public void Events_default_not_null()
        {
            var options = new BasicOptions();
            Assert.NotNull(options.Events);
        }

        [Fact]
        public void SuppressWWWAuthenticateHeader_default_false()
        {
            var options = new BasicOptions();
            Assert.False(options.SuppressWWWAuthenticateHeader);
        }

        [Fact]
        public async Task SuppressWWWAuthenticateHeader_verify_false()
        {
            var realm = TestServerBuilder.Realm;
            using var server = TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = realm;
                options.SuppressWWWAuthenticateHeader = false;
            });

            using var client = server.CreateClient();
            using var response = await client.GetAsync(TestServerBuilder.BaseUrl);
            
            Assert.False(response.IsSuccessStatusCode);

            var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
            Assert.NotEmpty(wwwAuthenticateHeader);

            var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
            Assert.NotNull(wwwAuthenticateHeaderToMatch);
            Assert.Equal(BasicDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\"", wwwAuthenticateHeaderToMatch.Parameter);
        }

        [Fact]
        public async Task SuppressWWWAuthenticateHeader_verify_true()
        {
            var realm = TestServerBuilder.Realm;
            using var server = TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = realm;
                options.SuppressWWWAuthenticateHeader = true;
            });

            using var client = server.CreateClient();
            using var response = await client.GetAsync(TestServerBuilder.BaseUrl);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public void BasicUserValidationServiceType_default_null()
        {
            var options = new BasicOptions();
            Assert.Null(options.BasicUserValidationServiceType);
        }

        [Fact]
        public void BasicUserValidationServiceType_verify_null()
        {
            using var server = TestServerBuilder.BuildTestServer();
            var services = server.Host.Services;
            
            var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
            var apiKeyOptions = apiKeyOptionsSnapshot?.Get(BasicDefaults.AuthenticationScheme);
            Assert.NotNull(apiKeyOptions);
            Assert.Null(apiKeyOptions.BasicUserValidationServiceType);

            var apiKeyProvider = services.GetService<IBasicUserValidationService>();
            Assert.Null(apiKeyProvider);
        }

        [Fact]
        public void BasicUserValidationServiceType_verify_not_null()
        {
            using var server = TestServerBuilder.BuildTestServerWithService();
            var services = server.Host.Services;

            var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
            var apiKeyOptions = apiKeyOptionsSnapshot?.Get(BasicDefaults.AuthenticationScheme);
            Assert.NotNull(apiKeyOptions);
            Assert.NotNull(apiKeyOptions.BasicUserValidationServiceType);
            Assert.Equal(typeof(FakeBasicUserValidationService), apiKeyOptions.BasicUserValidationServiceType);

            var apiKeyProvider = services.GetService<IBasicUserValidationService>();
            Assert.NotNull(apiKeyProvider);
            Assert.Equal(typeof(FakeBasicUserValidationService), apiKeyProvider.GetType());
        }

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

        [Fact]
        public void IgnoreAuthenticationIfAllowAnonymous_default_false()
        {
            var options = new BasicOptions();
            Assert.False(options.IgnoreAuthenticationIfAllowAnonymous);
        }

        [Fact]
        public async Task IgnoreAuthenticationIfAllowAnonymous_verify_false()
        {
            var realm = TestServerBuilder.Realm;
            using var server = TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = realm;
                options.IgnoreAuthenticationIfAllowAnonymous = false;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.AnonymousUrl);
            request.Headers.Authorization = FakeUsers.FakeUserIgnoreAuthenticationIfAllowAnonymous.ToAuthenticationHeaderValue();

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));

            Assert.Equal(nameof(BasicOptions.IgnoreAuthenticationIfAllowAnonymous), exception.Message);
        }

        [Fact]
        public async Task IgnoreAuthenticationIfAllowAnonymous_verify_true()
        {
            var realm = TestServerBuilder.Realm;
            using var server = TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = realm;
                options.IgnoreAuthenticationIfAllowAnonymous = true;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.AnonymousUrl);
            request.Headers.Authorization = FakeUsers.FakeUserIgnoreAuthenticationIfAllowAnonymous.ToAuthenticationHeaderValue();
            using var response = await client.SendAsync(request);

            Assert.True(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

#endif

    }
}

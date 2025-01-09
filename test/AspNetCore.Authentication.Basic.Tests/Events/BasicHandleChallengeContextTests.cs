// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using AspNetCore.Authentication.Basic.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using System.Net;
using System.Net.Http;
using Xunit;

namespace AspNetCore.Authentication.Basic.Tests.Events
{
    public class BasicHandleChallengeContextTests : IDisposable
    {
        private readonly List<TestServer> _serversToDispose = [];

        public void Dispose()
        {
            _serversToDispose.ForEach(s => s.Dispose());
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task Handled()
        {
            using var client = BuildClient(
                context =>
                {
                    Assert.False(context.IsHandled);

                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    context.Handled();

                    Assert.True(context.IsHandled);

                    return Task.CompletedTask;
                }
            );
            
            using var response = await client.GetAsync(TestServerBuilder.BaseUrl);
            
            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Handled_not_called()
        {
            using var client = BuildClient(
                context =>
                {
                    Assert.False(context.IsHandled);

                    context.Response.StatusCode = StatusCodes.Status400BadRequest;

                    return Task.CompletedTask;
                }
            );

            using var response = await client.GetAsync(TestServerBuilder.BaseUrl);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }



        private HttpClient BuildClient(Func<BasicHandleChallengeContext, Task> onHandleChallenge)
        {
            var server = TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = TestServerBuilder.Realm;
                options.Events.OnHandleChallenge = onHandleChallenge;
            });

            _serversToDispose.Add(server);
            return server.CreateClient();
        }
    }
}

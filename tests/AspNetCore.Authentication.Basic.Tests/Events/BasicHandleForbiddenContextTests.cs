// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Events
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.TestHost;
    using Xunit;

    public class BasicHandleForbiddenContextTests : IDisposable
    {
        private readonly List<TestServer> _serversToDispose = new List<TestServer>();

        public void Dispose()
        {
            _serversToDispose.ForEach(s => s.Dispose());
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

            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
            request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
            using var response = await client.SendAsync(request);
            
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

            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
            request.Headers.Authorization = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.FakeUsers.FakeUser.ToAuthenticationHeaderValue();
            using var response = await client.SendAsync(request);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }



        private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicHandleForbiddenContext, Task> onHandleForbidden)
        {
            var server = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.BuildTestServerWithService(options =>
            {
                options.Realm = MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure.TestServerBuilder.Realm;
                options.Events.OnHandleForbidden = onHandleForbidden;
            });

            _serversToDispose.Add(server);
            return server.CreateClient();
        }
    }
}

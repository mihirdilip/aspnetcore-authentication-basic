using AspNetCore.Authentication.Basic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SampleWebApi.Repositories;
using SampleWebApi.Services;

namespace SampleWebApi_3_1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add User repository to the dependency container.
            services.AddTransient<IUserRepository, InMemoryUserRepository>();

            // Add the Basic scheme authentication here..
            // AddBasic extension takes an implementation of IBasicUserValidationService for validating the username and password. 
            // It also requires Realm to be set in the options.
            services.AddAuthentication(BasicDefaults.AuthenticationScheme)
                .AddBasic<BasicUserValidationService>(options => { options.Realm = "Sample Web API"; });

            services.AddControllers(options =>
            {
                // ALWAYS USE HTTPS (SSL) protocol in production when using Basic authentication.
                //options.Filters.Add<RequireHttpsAttribute>();

                // All the requests will need to be authorized. 
                // Alternatively, add [Authorize] attribute to Controller or Action Method where necessary.
                options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
            }); //.AddXmlSerializerFormatters()   // To enable XML along with JSON;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // The below order of pipeline chain is important!

            app.UseHttpsRedirection();
            app.UseRouting();
            
            app.UseAuthentication();    // NOTE: DEFAULT TEMPLATE DOES NOT HAVE THIS, THIS LINE IS REQUIRED AND HAS TO BE ADDED!!!

            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

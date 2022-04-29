using System.Diagnostics;
using AspNetCore.Authentication.Basic;
using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;

namespace SampleWebApi.Services
{
	internal class BasicUserAuthenticationServiceFactory : IBasicUserAuthenticationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IUserRepository userRepository;

		public BasicUserAuthenticationServiceFactory(ILoggerFactory loggerFactory, IUserRepository userRepository)
		{
			this.loggerFactory = loggerFactory;
			this.userRepository = userRepository;
		}

		/// <inheritdoc />
		public IBasicUserAuthenticationService CreateBasicUserValidationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new BasicUserAuthenticationService(this.loggerFactory.CreateLogger<BasicUserAuthenticationService>(), this.userRepository);
		}
	}
}

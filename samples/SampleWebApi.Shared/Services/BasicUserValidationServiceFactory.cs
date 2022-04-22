using System.Diagnostics;
using AspNetCore.Authentication.Basic;
using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;

namespace SampleWebApi.Services
{
	internal class BasicUserValidationServiceFactory : IBasicUserValidationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IUserRepository userRepository;

		public BasicUserValidationServiceFactory(ILoggerFactory loggerFactory, IUserRepository userRepository)
		{
			this.loggerFactory = loggerFactory;
			this.userRepository = userRepository;
		}

		/// <inheritdoc />
		public IBasicUserValidationService CreateBasicUserValidationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new BasicUserValidationService(this.loggerFactory.CreateLogger<BasicUserValidationService>(), this.userRepository);
		}
	}
}

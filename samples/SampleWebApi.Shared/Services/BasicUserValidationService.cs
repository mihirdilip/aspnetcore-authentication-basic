using AspNetCore.Authentication.Basic;
using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;
using System;
using System.Threading.Tasks;

namespace SampleWebApi.Services
{
	internal class BasicUserValidationService : IBasicUserValidationService
	{
		private readonly ILogger<BasicUserValidationService> _logger;
		private readonly IUserRepository _userRepository;

		public BasicUserValidationService(ILogger<BasicUserValidationService> logger, IUserRepository userRepository)
		{
			_logger = logger;
			_userRepository = userRepository;
		}

		public async Task<bool> IsValidAsync(string username, string password)
		{
			try
			{
				// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
				// Write your implementation here and return true or false depending on the validation..
				var user = await _userRepository.GetUserByUsername(username);
				var isValid = user != null && user.Password == password;
				return isValid;
			}
			catch (Exception e)
			{
				_logger.LogError(e, e.Message);
				throw;
			}
		}
	}
}
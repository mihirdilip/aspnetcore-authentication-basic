#pragma warning disable CS8619 // Nullability of reference types in value doesn't match target type.
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SampleWebApi.Models;

namespace SampleWebApi.Repositories
{
	/// <summary>
	/// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
	/// </summary>
	public class InMemoryUserRepository : IUserRepository
	{
		private readonly List<User> _users = new List<User>
		{
			new User { Username = "TestUser1", Password = "1234" },
			new User { Username = "TestUser2", Password = "1234" },
			new User { Username = "TestUser3", Password = "1234" },
			new User { Username = "TestUser4", Password = "1234" }
		};


		public Task<User> GetUserByUsername(string username)
		{
			return Task.FromResult(_users.FirstOrDefault(u => u.Username == username));
		}

		public Task<IEnumerable<User>> GetUsers()
		{
			return Task.FromResult<IEnumerable<User>>(_users);
		}
	}
}
#pragma warning restore CS8619 // Nullability of reference types in value doesn't match target type.
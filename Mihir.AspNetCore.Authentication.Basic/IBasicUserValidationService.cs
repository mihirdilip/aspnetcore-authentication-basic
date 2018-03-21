using System.Threading.Tasks;

namespace Mihir.AspNetCore.Authentication.Basic
{
	public interface IBasicUserValidationService
	{
		Task<bool> IsValidAsync(string username, string password);
	}
}

using Microsoft.AspNetCore.Authentication;

namespace Mihir.AspNetCore.Authentication.Basic
{
	public class BasicOptions : AuthenticationSchemeOptions
	{
		public string Realm { get; set; }

		public string Challenge => $"{BasicDefaults.AuthenticationScheme} realm=\"{Realm}\", charset=\"UTF-8\"";

		//public new BasicEvents Events
		//{
		//	get => (BasicEvents)base.Events;
		//	set => base.Events = value;
		//}
	}
}

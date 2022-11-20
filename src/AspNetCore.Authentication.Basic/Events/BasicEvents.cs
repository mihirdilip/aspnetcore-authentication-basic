// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Events
{
	using System;
	using System.Threading.Tasks;

	/// <summary>
	///     Basic Events.
	/// </summary>
	public class BasicEvents
	{
		/// <summary>
		///     A delegate assigned to this property will be invoked just before validating credentials.
		/// </summary>
		/// <remarks>
		///     You must provide a delegate for this property for authentication to occur.
		///     In your delegate you should either call context.ValidationSucceeded() which will handle construction of
		///     authentication principal from the user details which will be assigned the context.Principal property and call
		///     context.Success(),
		///     or construct an authentication principal from the user details &amp; attach it to the context.Principal property
		///     and finally call context.Success() method.
		///     If only context.Principal property set without calling context.Success() method then, Success() method is
		///     automatically called.
		/// </remarks>
		public Func<BasicValidateCredentialsContext, Task> OnValidateCredentials { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if
		///     OnValidateCredentials delegate is assigned.
		///     It can be used for adding claims, headers, etc to the response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing.
		/// </remarks>
		public Func<BasicAuthenticationSucceededContext, Task> OnAuthenticationSucceeded { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked when the authentication fails.
		/// </summary>
		public Func<BasicAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling
		///     unauthorized response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing and if you want to use custom implementation.
		///     Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question
		///     deals an authentication interaction as part of it's request flow. (like adding a response header, or
		///     changing the 401 result to 302 of a login page or external sign-in location.)
		///     Call context.Handled() at the end so that any default logic for this challenge will be skipped.
		/// </remarks>
		public Func<BasicHandleChallengeContext, Task> OnHandleChallenge { get; set; }

		/// <summary>
		///     A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.
		/// </summary>
		/// <remarks>
		///     Only use this if you know what you are doing and if you want to use custom implementation.
		///     Set the delegate to handle Forbid.
		///     Call context.Handled() at the end so that any default logic will be skipped.
		/// </remarks>
		public Func<BasicHandleForbiddenContext, Task> OnHandleForbidden { get; set; }


		/// <summary>
		///     Invoked when validating credentials.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public virtual Task ValidateCredentialsAsync(BasicValidateCredentialsContext context)
		{
			return this.OnValidateCredentials == null ? Task.CompletedTask : this.OnValidateCredentials(context);
		}

		/// <summary>
		///     Invoked when the authentication succeeds.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public virtual Task AuthenticationSucceededAsync(BasicAuthenticationSucceededContext context)
		{
			return this.OnAuthenticationSucceeded == null ? Task.CompletedTask : this.OnAuthenticationSucceeded(context);
		}

		/// <summary>
		///     Invoked when the authentication fails.
		/// </summary>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public virtual Task AuthenticationFailedAsync(BasicAuthenticationFailedContext context)
		{
			return this.OnAuthenticationFailed == null ? Task.CompletedTask : this.OnAuthenticationFailed(context);
		}

		/// <summary>
		///     Invoked before a challenge is sent back to the caller when handling unauthorized response.
		/// </summary>
		/// <remarks>
		///     Override this method to deal with 401 challenge concerns, if an authentication scheme in question
		///     deals an authentication interaction as part of it's request flow. (like adding a response header, or
		///     changing the 401 result to 302 of a login page or external sign-in location.)
		///     Call context.Handled() at the end so that any default logic for this challenge will be skipped.
		/// </remarks>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public virtual Task HandleChallengeAsync(BasicHandleChallengeContext context)
		{
			return this.OnHandleChallenge == null ? Task.CompletedTask : this.OnHandleChallenge(context);
		}

		/// <summary>
		///     Invoked if Authorization fails and results in a Forbidden response.
		/// </summary>
		/// <remarks>
		///     Override this method to handle Forbid.
		///     Call context.Handled() at the end so that any default logic will be skipped.
		/// </remarks>
		/// <param name="context"></param>
		/// <returns>A Task.</returns>
		public virtual Task HandleForbiddenAsync(BasicHandleForbiddenContext context)
		{
			return this.OnHandleForbidden == null ? Task.CompletedTask : this.OnHandleForbidden(context);
		}
	}
}

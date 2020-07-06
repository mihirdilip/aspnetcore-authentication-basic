// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Basic Events.
    /// </summary>
    public class BasicEvents 
    {
        /// <summary>
        /// A delegate assigned to this property will be invoked just before validating credentials. 
        /// </summary>
        /// <remarks>
        /// You must provide a delegate for this property for authentication to occur.
        /// In your delegate you should construct an authentication principal from the user details,
        /// attach it to the context.Principal property and finally call context.Success(); it will be returned as it is.
        /// If only context.Principal property set then ticket is automatically created and returned.
        /// context.ValidationSucceeded() for valid credentials or context.ValidationFailed() for invalid credentials can be called when context.Principal property is not set.
        /// </remarks>
        public Func<BasicValidateCredentialsContext, Task> OnValidateCredentials { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if OnValidateCredentials delegate is assigned.
        /// It can be used for adding claims, etc.
        /// </summary>
        /// <remarks>
        /// Only use this if you know what you are doing.
        /// </remarks>
        public Func<BasicAuthenticationSucceededContext, Task> OnAuthenticationSucceeded { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked when the authentication fails.
        /// </summary>
        public Func<BasicAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling unauthenticated response.
        /// </summary>
        /// <remarks>
        /// Only use this if you know what you are doing and if you want to use custom implementation.
        /// Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// Call context.Handled() at the end so that any default logic for this challenge will be skipped.
        /// </remarks>
        public Func<BasicHandleChallengeContext, Task> OnHandleChallenge { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.
        /// </summary>
        /// <remarks>
        /// Only use this if you know what you are doing and if you want to use custom implementation.
        /// Set the delegate to handle Forbid.
        /// Call context.Handled() at the end so that any default logic will be skipped.
        /// </remarks>
        public Func<BasicHandleForbiddenContext, Task> OnHandleForbidden { get; set; } = context => Task.CompletedTask;





        /// <summary>
        /// Invoked when validating credentials.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A Task.</returns>
        public virtual Task ValidateCredentialsAsync(BasicValidateCredentialsContext context) => OnValidateCredentials == null ? Task.CompletedTask : OnValidateCredentials(context);

        /// <summary>
        /// Invoked when the authentication succeeds.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A Task.</returns>
        public virtual Task AuthenticationSucceededAsync(BasicAuthenticationSucceededContext context) => OnAuthenticationSucceeded == null ? Task.CompletedTask : OnAuthenticationSucceeded(context);

        /// <summary>
        /// Invoked when the authentication fails.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A Task.</returns>
        public virtual Task AuthenticationFailedAsync(BasicAuthenticationFailedContext context) => OnAuthenticationFailed == null ? Task.CompletedTask : OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked before a challenge is sent back to the caller when handling unauthenticated response.
        /// </summary>
        /// <remarks>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// Call context.Handled() at the end so that any default logic for this challenge will be skipped.
        /// </remarks>
        /// <param name="context"></param>
        /// <returns>A Task.</returns>
        public virtual Task HandleChallengeAsync(BasicHandleChallengeContext context) => OnHandleChallenge == null ? Task.CompletedTask : OnHandleChallenge(context);

        /// <summary>
        /// Invoked if Authorization fails and results in a Forbidden response.
        /// </summary>
        /// <remarks>
        /// Override this method to handle Forbid.
        /// Call context.Handled() at the end so that any default logic will be skipped.
        /// </remarks>
        /// <param name="context"></param>
        /// <returns>A Task.</returns>
        public virtual Task HandleForbiddenAsync(BasicHandleForbiddenContext context) => OnHandleForbidden == null ? Task.CompletedTask : OnHandleForbidden(context);
    }
}

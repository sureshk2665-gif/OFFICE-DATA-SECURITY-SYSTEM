using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class AuthEndpoints
{
    public const string SignInRateLimit = "sign-in";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var anonymous = app.MapGroup(string.Empty).AllowAnonymous().RequireRateLimiting(SignInRateLimit).WithTags("Authentication");

        anonymous.MapGet(ApiRoutes.SetupStatus, async (AuthService auth, CancellationToken ct) =>
            TypedResults.Ok(new SetupStatusResponse(await auth.IsFirstAdminSetupRequiredAsync(ct))));

        anonymous.MapPost(ApiRoutes.SetupFirstAdmin, async (FirstAdminSetupRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.CreateFirstAdminAsync(request, http.ToRequestContext(), ct)).ToHttp());

        anonymous.MapPost(ApiRoutes.AdminActivate, async (AdminActivateRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.ActivateAdminAsync(request, http.ToRequestContext(), ct)).ToHttp());

        anonymous.MapPost(ApiRoutes.AdminConfirmMfa, async (ConfirmMfaRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.ConfirmAdminMfaAsync(request, http.ToRequestContext(), ct)).ToHttpNoContent());

        anonymous.MapPost(ApiRoutes.AdminLogin, async (AdminLoginRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.AdminLoginAsync(request, http.ToRequestContext(), ct)).ToHttp());

        anonymous.MapPost(ApiRoutes.AdminMfa, async (AdminMfaRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.AdminMfaAsync(request, http.ToRequestContext(), ct)).ToHttp());

        anonymous.MapPost(ApiRoutes.StaffLogin, async (StaffLoginRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.StaffLoginAsync(request, http.ToRequestContext(), ct)).ToHttp());

        anonymous.MapPost(ApiRoutes.StaffActivate, async (StaffActivateRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.StaffActivateAsync(request, http.ToRequestContext(), ct)).ToHttp());

        // Any signed-in administrator or staff member (fallback policy).
        var signedIn = app.MapGroup(string.Empty).WithTags("Authentication");

        signedIn.MapGet(ApiRoutes.Me, (HttpContext http) => TypedResults.Ok(AuthService.ToUser(http.RequirePrincipal())));

        signedIn.MapPost(ApiRoutes.Logout, async (AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            await auth.LogoutAsync(http.ToRequestContext(), ct);
            return TypedResults.NoContent();
        });

        signedIn.MapPost(ApiRoutes.ChangePassword, async (ChangePasswordRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
            (await auth.ChangePasswordAsync(request, http.ToRequestContext(), ct)).ToHttpNoContent());
    }
}

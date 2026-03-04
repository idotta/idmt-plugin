namespace Idmt.Plugin.Features.Admin;

public sealed record TenantInfoResponse(
    string Id,
    string Identifier,
    string Name,
    string Plan,
    bool IsActive
);

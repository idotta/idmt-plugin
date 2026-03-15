namespace Idmt.Plugin.Features.Admin;

public sealed record TenantInfoResponse(
    string Id,
    string Identifier,
    string Name,
    string Plan,
    bool IsActive
);

/// <summary>
/// Generic paginated response envelope.
/// </summary>
/// <typeparam name="T">The item type contained in the page.</typeparam>
/// <param name="Items">The items on the current page.</param>
/// <param name="TotalCount">Total number of matching items across all pages.</param>
/// <param name="Page">The 1-based current page number.</param>
/// <param name="PageSize">The maximum number of items per page (capped at 100).</param>
/// <param name="HasMore">True when additional pages exist after this one.</param>
public sealed record PaginatedResponse<T>(
    IReadOnlyList<T> Items,
    int TotalCount,
    int Page,
    int PageSize,
    bool HasMore
);

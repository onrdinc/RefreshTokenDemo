using DemoRefreshToken.Models.DTO;
using System.Security.Claims;

namespace DemoRefreshToken.Repository.Abstract
{
    public interface ITokenService
    {
        TokenResponse GetToken(IEnumerable<Claim> claim);
        string GetRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}

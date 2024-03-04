namespace DemoRefreshToken.Models.DTO
{
    public class TokenResponse
    {
        public string? Token { get; set; }
        public DateTime ValidTo { get; set; }
    }
}

namespace JwtWebApi
{
    public class RefreshToken
    {
        public string token { set; get; } = string.Empty;
        public DateTime Created { set; get; } = DateTime.UtcNow;
        public DateTime Expires { set; get; } 

    }
}

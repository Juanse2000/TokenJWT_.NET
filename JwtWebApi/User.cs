namespace JwtWebApi
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; } 
        public byte[] PasswordSalt { get; set;}
        public string RefreshToken { set; get; } = string.Empty;
        public DateTime TokenCreated { set; get; } = DateTime.UtcNow;
        public DateTime TokenExpires { set; get; }
    }
}

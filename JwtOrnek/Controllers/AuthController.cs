using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtOrnek.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        string signingKey = "BuBenimSigningKeyDENEMETarzındaOrnekKey";

        [HttpGet]
        public string Get(string userName, string password)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(JwtRegisteredClaimNames.Email,userName),
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "jwtornekproje",
                audience: "BuBenimKullandığımAudianceDegeri",
                claims: claims,
                expires: DateTime.Now.AddDays(15),
                notBefore: DateTime.Now,
                signingCredentials: credentials
                );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }

        [HttpGet("ValidateToken")]
        public bool ValidateToken(string token)
        {
            var securirtyKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            try
            {
                JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
                securityTokenHandler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securirtyKey,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false
                }, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims = jwtToken.Claims.ToList();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}

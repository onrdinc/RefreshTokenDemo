﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace DemoRefreshToken.Controllers
{
    [Route("api/[controller]/{action}")]
    [ApiController]
    [Authorize(Roles ="admin")]
    public class AdminController : ControllerBase
    {
        public IActionResult GetData()
        {
            return Ok("Data from admin controller");
        }
    }
}

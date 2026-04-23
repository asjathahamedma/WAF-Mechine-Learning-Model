using Microsoft.AspNetCore.Mvc;
using SmartEventMVC.Models;

public class AccountController : Controller
{
    private readonly SmartEventDbContext _context;

    public AccountController(SmartEventDbContext context) => _context = context;

    public IActionResult Login() => View();

    [HttpPost]
    public IActionResult Login(string mobile, string password)
    {
        var member = _context.Members
            .FirstOrDefault(m => m.Mobile == mobile && m.Password == password);

        if (member != null)
        {
            HttpContext.Session.SetInt32("MemberId", member.MemberId);
            HttpContext.Session.SetString("Mobile", member.Mobile);
            HttpContext.Session.SetString("MemberName", member.Name);
            return RedirectToAction("Index", "Home");
        }

        ViewBag.Error = "Invalid mobile or password";
        return View();
    }

    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }

 
}
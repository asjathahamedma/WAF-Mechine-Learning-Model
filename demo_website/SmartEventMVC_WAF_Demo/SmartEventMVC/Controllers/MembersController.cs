using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using SmartEventMVC.Models;

namespace SmartEventMVC.Controllers
{
    public class MembersController : Controller
    {
        private readonly SmartEventDbContext _context;

        public MembersController(SmartEventDbContext context)
        {
            _context = context;
        }

        // GET: Members (Admin only)
        public async Task<IActionResult> Index()
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            return View(await _context.Members.ToListAsync());
        }

        // GET: Members/Details/5 (Admin only)
        public async Task<IActionResult> Details(int? id)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            if (id == null)
            {
                return NotFound();
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.MemberId == id);
            if (member == null)
            {
                return NotFound();
            }

            return View(member);
        }

        // GET: Members/Create (Public registration)
        public IActionResult Create()
        {
            return View();
        }

        // POST: Members/Create (Public registration)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("MemberId,Name,Mobile,Password")] Member member)
        {
            if (ModelState.IsValid)
            {
                // Check if mobile already exists
                var existingMember = await _context.Members
                    .FirstOrDefaultAsync(m => m.Mobile == member.Mobile);

                if (existingMember != null)
                {
                    ModelState.AddModelError("Mobile", "Mobile number already registered.");
                    return View(member);
                }

                _context.Add(member);
                await _context.SaveChangesAsync();

                TempData["Success"] = "Registration successful! Please login to continue.";
                return RedirectToAction("Login", "Account");
            }
            return View(member);
        }

        // GET: Members/Edit/5 (Admin only)
        public async Task<IActionResult> Edit(int? id)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            if (id == null)
            {
                return NotFound();
            }

            var member = await _context.Members.FindAsync(id);
            if (member == null)
            {
                return NotFound();
            }
            return View(member);
        }

        // POST: Members/Edit/5 (Admin only)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("MemberId,Name,Mobile,Password")] Member member)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            if (id != member.MemberId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Get the existing member to preserve any fields not in the bind
                    var existingMember = await _context.Members.FindAsync(id);
                    if (existingMember == null)
                    {
                        return NotFound();
                    }

                    // Check if trying to change mobile number (shouldn't be allowed)
                    if (existingMember.Mobile != member.Mobile)
                    {
                        // Check if new mobile already exists
                        var duplicateMobile = await _context.Members
                            .FirstOrDefaultAsync(m => m.Mobile == member.Mobile && m.MemberId != id);

                        if (duplicateMobile != null)
                        {
                            ModelState.AddModelError("Mobile", "Mobile number already belongs to another member.");
                            return View(member);
                        }
                    }

                    // Update only the allowed fields
                    existingMember.Name = member.Name;
                    existingMember.Mobile = member.Mobile; // Allow admin to change mobile

                    // Only update password if provided
                    if (!string.IsNullOrEmpty(member.Password))
                    {
                        existingMember.Password = member.Password;
                    }

                    _context.Update(existingMember);
                    await _context.SaveChangesAsync();

                    TempData["Success"] = "Member updated successfully.";
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!MemberExists(member.MemberId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(member);
        }

        // GET: Members/Delete/5 (Admin only)
        public async Task<IActionResult> Delete(int? id)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            if (id == null)
            {
                return NotFound();
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.MemberId == id);
            if (member == null)
            {
                return NotFound();
            }

            return View(member);
        }

        // POST: Members/Delete/5 (Admin only)
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            var member = await _context.Members.FindAsync(id);
            if (member != null)
            {
                _context.Members.Remove(member);
            }

            await _context.SaveChangesAsync();
            TempData["Success"] = "Member deleted successfully.";
            return RedirectToAction(nameof(Index));
        }

        private bool MemberExists(int id)
        {
            return _context.Members.Any(e => e.MemberId == id);
        }
    }
}
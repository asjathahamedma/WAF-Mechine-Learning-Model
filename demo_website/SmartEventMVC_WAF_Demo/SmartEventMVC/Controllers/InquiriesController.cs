using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SmartEventMVC.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SmartEventMVC.Controllers
{
    public class InquiriesController : Controller
    {
        private readonly SmartEventDbContext _context;

        public InquiriesController(SmartEventDbContext context)
        {
            _context = context;
        }

        // GET: Inquiries (Admin only - All inquiries)
        public async Task<IActionResult> Index(string status = "All")
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            var inquiries = _context.Inquiries
                .Include(i => i.Event)
                .OrderByDescending(i => i.InquiryDate)
                .AsQueryable();

            // Filter by status
            if (status == "Pending")
            {
                inquiries = inquiries.Where(i => i.Status == "Pending");
            }
            else if (status == "Answered")
            {
                inquiries = inquiries.Where(i => i.Status == "Answered");
            }

            ViewBag.StatusFilter = status;
            ViewBag.PendingCount = await _context.Inquiries.CountAsync(i => i.Status == "Pending");

            return View(await inquiries.ToListAsync());
        }

        // GET: Inquiries/MyInquiries (User's own inquiries)
        public async Task<IActionResult> MyInquiries()
        {
            // Check if user is logged in
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var mobile = HttpContext.Session.GetString("Mobile");

            if (memberId == null || string.IsNullOrEmpty(mobile))
            {
                TempData["Error"] = "Please login to view your inquiries.";
                return RedirectToAction("Login", "Account");
            }

            // Get user's inquiries based on their mobile number
            var inquiries = await _context.Inquiries
                .Include(i => i.Event)
                .Where(i => i.Mobile == mobile)
                .OrderByDescending(i => i.InquiryDate)
                .ToListAsync();

            return View(inquiries);
        }

        // GET: Inquiries/Create?eventId=5
        public IActionResult Create(int? eventId)
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var mobile = HttpContext.Session.GetString("Mobile");

            // If user is logged in, pre-fill their info
            if (memberId != null && !string.IsNullOrEmpty(mobile))
            {
                var member = _context.Members.FirstOrDefault(m => m.Mobile == mobile);
                ViewBag.PrefillName = member?.Name;
                ViewBag.PrefillMobile = mobile;
            }
            else
            {
                ViewBag.PrefillName = "";
                ViewBag.PrefillMobile = "";
            }

            ViewBag.EventId = eventId;

            // Get event title if eventId is provided
            if (eventId.HasValue)
            {
                var eventObj = _context.Events.FirstOrDefault(e => e.EventId == eventId.Value);
                ViewBag.EventTitle = eventObj?.Title ?? "Event";
            }
            else
            {
                ViewBag.EventTitle = "General Inquiry";
            }

            return View();
        }

        // POST: Inquiries/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Inquiry inquiry)
        {
            if (ModelState.IsValid)
            {
                // Set default values
                inquiry.InquiryDate = DateTime.Now;
                inquiry.Status = "Pending";

                _context.Add(inquiry);
                await _context.SaveChangesAsync();

                TempData["Success"] = "Your inquiry has been submitted successfully! We'll get back to you soon.";

                // Redirect based on user type
                var mobile = HttpContext.Session.GetString("Mobile");
                if (!string.IsNullOrEmpty(mobile))
                {
                    return RedirectToAction("MyInquiries");
                }
                else
                {
                    if (inquiry.EventId.HasValue)
                    {
                        return RedirectToAction("Details", "Events", new { id = inquiry.EventId });
                    }
                    return RedirectToAction("Index", "Home");
                }
            }

            // If validation fails, repopulate ViewBag
            ViewBag.EventId = inquiry.EventId;
            if (inquiry.EventId.HasValue)
            {
                var eventObj = _context.Events.FirstOrDefault(e => e.EventId == inquiry.EventId.Value);
                ViewBag.EventTitle = eventObj?.Title ?? "Event";
            }
            else
            {
                ViewBag.EventTitle = "General Inquiry";
            }

            return View(inquiry);
        }

        // GET: Inquiries/Details/5 (Admin view with reply form)
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

            var inquiry = await _context.Inquiries
                .Include(i => i.Event)
                .FirstOrDefaultAsync(m => m.InquiryId == id);

            if (inquiry == null)
            {
                return NotFound();
            }

            return View(inquiry);
        }

        // POST: Inquiries/Reply/5 (Admin reply)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Reply(int id, string adminReply)
        {
            // Check if user is admin
            var mobile = HttpContext.Session.GetString("Mobile");
            if (mobile != "0711111111")
            {
                TempData["Error"] = "Access denied. Admin only.";
                return RedirectToAction("Login", "Account");
            }

            if (string.IsNullOrWhiteSpace(adminReply))
            {
                TempData["Error"] = "Reply cannot be empty.";
                return RedirectToAction("Details", new { id });
            }

            var inquiry = await _context.Inquiries.FindAsync(id);
            if (inquiry == null)
            {
                return NotFound();
            }

            // Update inquiry with reply
            inquiry.AdminReply = adminReply;
            inquiry.ReplyDate = DateTime.Now;
            inquiry.RepliedBy = "Admin";
            inquiry.Status = "Answered";

            _context.Update(inquiry);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Reply sent successfully!";
            return RedirectToAction("Details", new { id });
        }

        // GET: Inquiries/Delete/5 (Admin only)
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

            var inquiry = await _context.Inquiries
                .Include(i => i.Event)
                .FirstOrDefaultAsync(m => m.InquiryId == id);

            if (inquiry == null)
            {
                return NotFound();
            }

            return View(inquiry);
        }

        // POST: Inquiries/Delete/5
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

            var inquiry = await _context.Inquiries.FindAsync(id);
            if (inquiry != null)
            {
                _context.Inquiries.Remove(inquiry);
                await _context.SaveChangesAsync();
                TempData["Success"] = "Inquiry deleted successfully.";
            }

            return RedirectToAction(nameof(Index));
        }

        // GET: Inquiries/UserDetails/5 (User view of their inquiry)
        public async Task<IActionResult> UserDetails(int? id)
        {
            // Check if user is logged in
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var mobile = HttpContext.Session.GetString("Mobile");

            if (memberId == null || string.IsNullOrEmpty(mobile))
            {
                TempData["Error"] = "Please login to view your inquiry.";
                return RedirectToAction("Login", "Account");
            }

            if (id == null)
            {
                return NotFound();
            }

            var inquiry = await _context.Inquiries
                .Include(i => i.Event)
                .FirstOrDefaultAsync(m => m.InquiryId == id && m.Mobile == mobile);

            if (inquiry == null)
            {
                TempData["Error"] = "Inquiry not found or access denied.";
                return RedirectToAction("MyInquiries");
            }

            return View(inquiry);
        }
    }
}
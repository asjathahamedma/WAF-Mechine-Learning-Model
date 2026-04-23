using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SmartEventMVC.Models;

namespace SmartEventMVC.Controllers
{
    public class EventsController : Controller
    {
        private readonly SmartEventDbContext _context;

        public EventsController(SmartEventDbContext context)
        {
            _context = context;
        }

        // Helper method: Check if current user is admin
        private bool IsAdmin()
        {
            var mobile = HttpContext.Session.GetString("Mobile");
            return mobile == "0711111111"; // Hardcoded admin
        }

        // Helper: Check if user is logged in
        private bool IsLoggedIn()
        {
            return HttpContext.Session.GetInt32("MemberId") != null;
        }

        // GET: Events (with optional search)
        public async Task<IActionResult> Index(string searchString)
        {
            ViewData["CurrentFilter"] = searchString;

            var eventsQuery = from e in _context.Events
                              select e;

            if (!string.IsNullOrEmpty(searchString))
            {
                var search = searchString.Trim().ToLower();
                eventsQuery = eventsQuery.Where(e =>
                    e.Title.ToLower().Contains(search) ||
                    e.Description.ToLower().Contains(search) ||
                    e.Location.ToLower().Contains(search));
            }

            var events = await eventsQuery
                .OrderByDescending(e => e.EventDate)
                .ToListAsync();

            return View(events);
        }

        // GET: Events/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();

            var @event = await _context.Events
                .FirstOrDefaultAsync(e => e.EventId == id);

            if (@event == null) return NotFound();

            // Pass reviews to ViewData
            var reviews = await _context.Reviews
                .Include(r => r.Member)
                .Where(r => r.EventId == id)
                .ToListAsync();

            ViewData["Reviews"] = reviews;

            ViewBag.IsAdmin = IsAdmin();
            ViewBag.IsLoggedIn = IsLoggedIn();
            ViewBag.MemberId = HttpContext.Session.GetInt32("MemberId");

            var seatPrices = await _context.Seats
                .Where(s => s.EventId == id)
                .GroupBy(s => s.SeatType)
                .Select(g => new
                {
                    SeatType = g.Key,
                    Price = g.First().Price, // all seats of same type have same price
                    Count = g.Count()
                })
                .ToListAsync();

            ViewBag.SeatPrices = seatPrices;
            ViewBag.HasSeats = seatPrices.Any();

            return View(@event);
        }

        // GET: Events/Create - Admin only
        public IActionResult Create()
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));

            var viewModel = new EventCreateViewModel
            {
                Event = new Event(),
                SeatTypes = new List<SeatTypeInput>
                {
                    new SeatTypeInput() // start with one empty row
                }
            };

            return View(viewModel);
        }

        // POST: Events/Create - Admin only
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(EventCreateViewModel viewModel, IFormFile imageFile)
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));

            if (ModelState.IsValid)
            {
                // 1. Handle image upload
                if (imageFile != null && imageFile.Length > 0)
                {
                    string uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/images/events");
                    Directory.CreateDirectory(uploadsFolder);
                    string uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(imageFile.FileName);
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await imageFile.CopyToAsync(fileStream);
                    }

                    viewModel.Event.ImagePath = "/images/events/" + uniqueFileName;
                }
                else
                {
                    viewModel.Event.ImagePath = "/images/events/default.jpg";
                }

                // 2. Save the event
                _context.Add(viewModel.Event);
                await _context.SaveChangesAsync();

                // 3. Generate seats from seat types
                if (viewModel.SeatTypes != null && viewModel.SeatTypes.Any())
                {
                    var seatsToAdd = new List<Seat>();
                    foreach (var seatType in viewModel.SeatTypes)
                    {
                        if (string.IsNullOrWhiteSpace(seatType.SeatType) ||
                            seatType.Quantity <= 0 ||
                            seatType.Price < 0)
                        {
                            ModelState.AddModelError("",
                                $"Invalid data for seat type: {seatType.SeatType}. Please check quantity and price.");
                            return View(viewModel);
                        }

                        for (int i = 1; i <= seatType.Quantity; i++)
                        {
                            seatsToAdd.Add(new Seat
                            {
                                EventId = viewModel.Event.EventId,
                                SeatNumber = $"{seatType.SeatType}-{i}",
                                SeatType = seatType.SeatType,
                                Price = seatType.Price,
                                IsAvailable = true
                            });
                        }
                    }

                    _context.Seats.AddRange(seatsToAdd);
                    await _context.SaveChangesAsync();
                }

                return RedirectToAction(nameof(Index));
            }

            return View(viewModel);
        }

        // GET: Events/Edit/5 - Admin only
        public async Task<IActionResult> Edit(int? id)
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));
            if (id == null) return NotFound();

            var @event = await _context.Events.FindAsync(id);
            if (@event == null) return NotFound();

            return View(@event);
        }

        // POST: Events/Edit/5 - Admin only
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("EventId,Title,Description,EventDate,Location,Price,ImagePath")] Event @event)
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));
            if (id != @event.EventId) return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(@event);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!_context.Events.Any(e => e.EventId == id)) return NotFound();
                    else throw;
                }
                return RedirectToAction(nameof(Index));
            }

            return View(@event);
        }

        // GET: Events/Delete/5 - Admin only
        public async Task<IActionResult> Delete(int? id)
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));
            if (id == null) return NotFound();

            var @event = await _context.Events.FindAsync(id);
            if (@event == null) return NotFound();

            // Check if there are dependencies
            bool hasDependencies = _context.Bookings.Any(b => b.EventId == id)
                                || _context.Seats.Any(s => s.EventId == id)
                                || _context.Reviews.Any(r => r.EventId == id)
                                || _context.Inquiries.Any(i => i.EventId == id);

            ViewBag.HasDependencies = hasDependencies;

            return View(@event);
        }

        // POST: Events/Delete/5 - Admin only
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (!IsAdmin()) return RedirectToAction(nameof(Index));

            var @event = await _context.Events.FindAsync(id);
            if (@event == null)
            {
                return NotFound();
            }

            // ── Delete the image file if it exists and is not default ──
            if (!string.IsNullOrWhiteSpace(@event.ImagePath) &&
                !@event.ImagePath.EndsWith("/default.jpg", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    // Convert virtual path → physical path
                    // e.g. "/images/events/abc123.jpg" → "C:\...\wwwroot\images\events\abc123.jpg"
                    var physicalPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot",
                        @event.ImagePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));

                    if (System.IO.File.Exists(physicalPath))
                    {
                        System.IO.File.Delete(physicalPath);
                    }
                }
                catch (Exception ex)
                {
      
                    Console.WriteLine($"Image delete failed: {ex.Message}");
                }
            }

            // ── Delete related data (your existing code) ──
            var bookings = _context.Bookings.Where(b => b.EventId == id).ToList();
            foreach (var booking in bookings)
            {
                var bookingSeats = _context.BookingSeats.Where(bs => bs.BookingId == booking.BookingId);
                _context.BookingSeats.RemoveRange(bookingSeats);
            }

            _context.Bookings.RemoveRange(bookings);

            var seats = _context.Seats.Where(s => s.EventId == id);
            _context.Seats.RemoveRange(seats);

            var reviews = _context.Reviews.Where(r => r.EventId == id);
            _context.Reviews.RemoveRange(reviews);

            var inquiries = _context.Inquiries.Where(i => i.EventId == id);
            _context.Inquiries.RemoveRange(inquiries);

            // Finally remove the event
            _context.Events.Remove(@event);

            await _context.SaveChangesAsync();

            // Optional: success message
            TempData["Success"] = $"Event '{@event.Title}' and its image were deleted successfully.";

            return RedirectToAction(nameof(Index));
        }
    }
}
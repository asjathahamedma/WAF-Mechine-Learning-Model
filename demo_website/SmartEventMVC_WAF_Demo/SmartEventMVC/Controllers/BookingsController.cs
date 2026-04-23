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
    public class BookingsController : Controller
    {
        private readonly SmartEventDbContext _context;

        public BookingsController(SmartEventDbContext context)
        {
            _context = context;
        }

        // Helper: Is current user admin?
        private bool IsAdmin()
        {
            var mobile = HttpContext.Session.GetString("Mobile");
            return mobile == "0711111111";
        }

        // Helper: Is this booking owned by current user?
        private bool IsOwnBooking(Booking booking)
        {
            var currentMemberId = HttpContext.Session.GetInt32("MemberId");
            return currentMemberId != null && booking.MemberId == currentMemberId.Value;
        }

        // GET: Bookings (My Bookings for normal users, All for admin)
        public async Task<IActionResult> Index()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (memberId == null)
            {
                return RedirectToAction("Login", "Account", new { returnUrl = "/Bookings" });
            }

            var baseQuery = _context.Bookings
                .Include(b => b.Event)
                .Include(b => b.Member);

            IQueryable<Booking> finalQuery = baseQuery;

            if (!IsAdmin())
            {
                finalQuery = baseQuery.Where(b => b.MemberId == memberId.Value);
            }

            var bookings = await finalQuery
                .OrderByDescending(b => b.BookingDate)
                .ToListAsync();

            ViewBag.IsAdmin = IsAdmin();
            ViewBag.PageTitle = IsAdmin() ? "All Bookings (Admin)" : "My Bookings";

            return View(bookings);
        }

        // GET: Bookings/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();

            var booking = await _context.Bookings
                .Include(b => b.Event)
                .Include(b => b.Member)
                .FirstOrDefaultAsync(b => b.BookingId == id);

            if (booking == null) return NotFound();

            if (!IsAdmin() && !IsOwnBooking(booking))
            {
                TempData["Error"] = "You are not authorized to view this booking.";
                return RedirectToAction(nameof(Index));
            }

            return View(booking);
        }

        // GET: Bookings/SelectSeats?eventId=5
        public async Task<IActionResult> SelectSeats(int? eventId)
        {
            if (eventId == null)
                return NotFound("Event ID is required.");

            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (memberId == null)
            {
                return RedirectToAction("Login", "Account",
                    new { returnUrl = $"/Bookings/SelectSeats?eventId={eventId}" });
            }

            var evt = await _context.Events.FindAsync(eventId);
            if (evt == null)
                return NotFound("Event not found.");

            // Get ALL seats for this event with their individual prices
            var allSeats = await _context.Seats
                .Where(s => s.EventId == eventId)
                .ToListAsync();

            // Get booked seat IDs
            var bookedSeatIds = allSeats
                .Where(s => s.IsAvailable == false)
                .Select(s => s.SeatId)
                .ToList();

            // Calculate price ranges for display
            var minPrice = allSeats.Any() ? allSeats.Min(s => s.Price) : 0;
            var maxPrice = allSeats.Any() ? allSeats.Max(s => s.Price) : 0;

            // Group prices by seat type
            var seatTypePrices = allSeats
                .GroupBy(s => s.SeatType)
                .ToDictionary(g => g.Key, g => g.First().Price);

            ViewBag.Event = evt;
            ViewBag.EventId = eventId;
            ViewBag.MemberId = memberId;
            ViewBag.AllSeats = allSeats;
            ViewBag.BookedSeatIds = bookedSeatIds;
            ViewBag.SeatTypePrices = seatTypePrices;
            ViewBag.MinPrice = minPrice;
            ViewBag.MaxPrice = maxPrice;

            return View("SeatSelection");
        }

        // POST: Bookings/SelectSeats
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SelectSeats(int eventId, int[] selectedSeatIds)
        {
            if (selectedSeatIds == null || selectedSeatIds.Length == 0)
            {
                TempData["Error"] = "Please select at least one seat.";
                return RedirectToAction("SelectSeats", new { eventId });
            }

            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (memberId == null)
                return RedirectToAction("Login", "Account");

            // Get selected seats from database to calculate total from individual prices
            var selectedSeats = await _context.Seats
                .Where(s => selectedSeatIds.Contains(s.SeatId))
                .ToListAsync();

            decimal total = selectedSeats.Sum(s => s.Price);

            HttpContext.Session.SetInt32("TempEventId", eventId);
            HttpContext.Session.SetInt32("TempMemberId", memberId.Value);
            HttpContext.Session.SetString("TempSelectedSeats", string.Join(",", selectedSeatIds));
            HttpContext.Session.SetString("TempTotalAmount", total.ToString("F2"));

            return RedirectToAction("Payment");
        }

        // GET: Bookings/Payment
        public IActionResult Payment()
        {
            var eventId = HttpContext.Session.GetInt32("TempEventId");
            if (eventId == null)
                return RedirectToAction("Index", "Home");

            ViewBag.TotalAmount = HttpContext.Session.GetString("TempTotalAmount");
            ViewBag.EventId = eventId;

            return View();
        }

        // POST: Bookings/Payment
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Payment(string paymentType)
        {
            var eventId = HttpContext.Session.GetInt32("TempEventId");
            var memberId = HttpContext.Session.GetInt32("TempMemberId");
            var selectedSeatsStr = HttpContext.Session.GetString("TempSelectedSeats");
            var totalStr = HttpContext.Session.GetString("TempTotalAmount");

            if (eventId == null || memberId == null || string.IsNullOrEmpty(selectedSeatsStr))
                return RedirectToAction("Index", "Home");

            var selectedSeatIds = selectedSeatsStr.Split(',').Select(int.Parse).ToArray();
            decimal total = decimal.TryParse(totalStr, out var parsed) ? parsed : 0m;

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var booking = new Booking
                {
                    MemberId = memberId.Value,
                    EventId = eventId.Value,
                    TotalAmount = total,
                    PaymentType = paymentType,
                    BookingDate = DateTime.Now,
                    Status = "Confirmed"
                };

                _context.Bookings.Add(booking);
                await _context.SaveChangesAsync();

                foreach (var seatId in selectedSeatIds)
                {
                    _context.BookingSeats.Add(new BookingSeat
                    {
                        BookingId = booking.BookingId,
                        SeatId = seatId
                    });
                }
                await _context.SaveChangesAsync();

                //  Mark seats as unavailable
                var seatsToUpdate = await _context.Seats
                    .Where(s => selectedSeatIds.Contains(s.SeatId))
                    .ToListAsync();

                foreach (var seat in seatsToUpdate)
                {
                    seat.IsAvailable = false;
                }
                await _context.SaveChangesAsync();

                await transaction.CommitAsync();

                HttpContext.Session.Remove("TempEventId");
                HttpContext.Session.Remove("TempMemberId");
                HttpContext.Session.Remove("TempSelectedSeats");
                HttpContext.Session.Remove("TempTotalAmount");

                TempData["Success"] = $"Booking #{booking.BookingId} confirmed! Total: LKR {total:N2}";
                return RedirectToAction("Confirmation", new { id = booking.BookingId });
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        // GET: Bookings/Confirmation/5
        public async Task<IActionResult> Confirmation(int? id)
        {
            if (id == null) return NotFound();

            var booking = await _context.Bookings
                .Include(b => b.Event)
                .Include(b => b.Member)
                .FirstOrDefaultAsync(b => b.BookingId == id);

            if (booking == null) return NotFound();

            return View(booking);
        }

        // GET: Bookings/Edit/5 - Admin only
        public async Task<IActionResult> Edit(int? id)
        {
            if (!IsAdmin())
            {
                TempData["Error"] = "Access denied. Only admin can edit bookings.";
                return RedirectToAction(nameof(Index));
            }

            if (id == null) return NotFound();

            var booking = await _context.Bookings.FindAsync(id);
            if (booking == null) return NotFound();

            ViewBag.EventId = new SelectList(_context.Events, "EventId", "Title", booking.EventId);
            ViewBag.MemberId = new SelectList(_context.Members, "MemberId", "Mobile", booking.MemberId);
            return View(booking);
        }

        // POST: Bookings/Edit/5 - Admin only
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("BookingId,MemberId,EventId,TotalAmount,PaymentType,BookingDate,Status")] Booking booking)
        {
            if (!IsAdmin())
            {
                TempData["Error"] = "Access denied. Only admin can edit bookings.";
                return RedirectToAction(nameof(Index));
            }

            if (id != booking.BookingId) return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(booking);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!BookingExists(booking.BookingId)) return NotFound();
                    else throw;
                }
                return RedirectToAction(nameof(Index));
            }

            ViewBag.EventId = new SelectList(_context.Events, "EventId", "Title", booking.EventId);
            ViewBag.MemberId = new SelectList(_context.Members, "MemberId", "Mobile", booking.MemberId);
            return View(booking);
        }

        // GET: Bookings/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();

            var booking = await _context.Bookings
                .Include(b => b.BookingSeats)
                .FirstOrDefaultAsync(m => m.BookingId == id);

            if (booking == null) return NotFound();

            if (!IsAdmin() && !IsOwnBooking(booking))
            {
                TempData["Error"] = "You can only cancel your own bookings.";
                return RedirectToAction(nameof(Index));
            }

            return View(booking);
        }

        // POST: Bookings/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var booking = await _context.Bookings
                .Include(b => b.BookingSeats)
                .FirstOrDefaultAsync(b => b.BookingId == id);

            if (booking == null) return NotFound();

            if (!IsAdmin() && !IsOwnBooking(booking))
            {
                TempData["Error"] = "You can only cancel your own bookings.";
                return RedirectToAction(nameof(Index));
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Release seats (set IsAvailable = true)
                if (booking.BookingSeats != null && booking.BookingSeats.Any())
                {
                    var seatIds = booking.BookingSeats.Select(bs => bs.SeatId).ToList();
                    var seatsToRelease = await _context.Seats
                        .Where(s => seatIds.Contains(s.SeatId))
                        .ToListAsync();

                    foreach (var seat in seatsToRelease)
                    {
                        seat.IsAvailable = true;
                    }
                    await _context.SaveChangesAsync();

                    // 2. Remove BookingSeats
                    _context.BookingSeats.RemoveRange(booking.BookingSeats);
                }

                // 3. Remove booking
                _context.Bookings.Remove(booking);
                await _context.SaveChangesAsync();

                await transaction.CommitAsync();

                TempData["Success"] = "Booking canceled successfully. Seats are now available again.";
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }

            return RedirectToAction(nameof(Index));
        }

        private bool BookingExists(int id)
        {
            return _context.Bookings.Any(e => e.BookingId == id);
        }
    }
}
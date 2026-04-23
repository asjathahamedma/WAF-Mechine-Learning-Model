using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SmartEventMVC.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

public class HomeController : Controller
{
    private readonly SmartEventDbContext _context;

    public HomeController(SmartEventDbContext context)
    {
        _context = context;
    }

    // Change to async method
    public async Task<IActionResult> Index()
    {
        var today = DateOnly.FromDateTime(DateTime.Today);

        // Get upcoming events (today or future), ordered by date
        var upcomingEvents = await _context.Events
            .Where(e => e.EventDate >= today)
            .OrderBy(e => e.EventDate)
            .Take(3) 
            .ToListAsync();

        return View(upcomingEvents);
    }

    public IActionResult IndexSync()
    {
        var today = DateOnly.FromDateTime(DateTime.Today);

        // Get upcoming events (today or future), ordered by date
        var upcomingEvents = _context.Events
            .Where(e => e.EventDate >= today)
            .OrderBy(e => e.EventDate)
            .Take(3) // Limit to 6 events
            .ToList();

        return View("Index", upcomingEvents);
    }

}